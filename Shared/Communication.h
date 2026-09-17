#pragma once

/*++

Module Name:

    Communication.h

Abstract:

    The single wire contract between Kernel/SharedMemoryHandler and any
    user-mode consumer. This header is intentionally dependency free: no
    WDK headers, no Win32 headers, no CRT. It compiles in the kernel
    driver (C++), in a user-mode program (C or C++), and in anything
    else that speaks the mailbox.#define-free fixed width types keep
    every offset identical on both sides.

    The channel has three phases, in strict order:

        1.  Handshake (once, before driver load). The consumer allocates
            exactly SHM_MAILBOX_BYTES of committed read/write memory,
            zeroes it, fills the mailbox and message magics, sets
            Message.Status to SHM_STATUS_NONE and records a Nonce. It
            then writes one SHM_HANDSHAKE blob to the rendezvous value
            (see SHM_REG_KEY_PATH / SHM_REG_VALUE_NAME) and loads the
            driver. DriverEntry consumes the blob, locks the buffer and
            answers Message.Status = SHM_STATUS_OK with the Nonce
            echoed, then deletes the value. A consumer that never sees
            its Nonce echoed must assume the driver never mapped it.

        2.  Requests (steady state, zero syscalls). The consumer fills
            Message (Type, Seq, Phys, Size, Data), issues a barrier,
            then sets Header.Pending = 1 last. The NMI handler services
            exactly one outstanding request: it snapshots the message,
            validates it, executes it, writes Status (and response
            Data), issues a barrier, then clears Pending last. The
            consumer polls Pending == 0 (with a timeout), issues a
            barrier, then reads Status and Data. There is no queue:
            submitting while Pending == 1 corrupts the in-flight
            request, which is a consumer bug, not a protocol event.

        3.  Teardown. The consumer stops submitting and only then
            unloads the driver. A request in flight across unload is a
            consumer bug with a bugcheck as its prize.

    Request types: PING proves the path (its response carries the CR8
    sampled at service time, which is 15 if and only if the handler ran
    at HIGH_LEVEL, plus consumed-cycle, issue, served-request and
    uptime counters), READ_PHYS copies physical bytes into Data,
    WRITE_PHYS copies Data out to physical bytes. Every transfer is
    bounded by SHM_MAX_TRANSFER so NMI service time stays bounded.

--*/

typedef unsigned long long SHM_U64;
typedef unsigned int SHM_U32;
typedef unsigned char SHM_U8;

//
// Wire magics. Three distinct constants so a misaligned or half written
// blob fails validation instead of aliasing another structure.
//

#define SHM_MAGIC_HANDSHAKE             0x48444B53484D0001ULL
#define SHM_MAGIC_MAILBOX               0x584F424D48530001ULL
#define SHM_MAGIC_MESSAGE               0x47534D4853000201ULL

//
// Request types accepted in SHM_MESSAGE.Type.
//

#define SHM_REQ_PING                    1U
#define SHM_REQ_READ_PHYS               2U
#define SHM_REQ_WRITE_PHYS              3U

//
// Completion codes written to SHM_MESSAGE.Status by the NMI handler.
// SHM_STATUS_NONE is the consumer's pre-handshake sentinel: it is never
// written by the kernel side, so observing it means no answer arrived.
//

#define SHM_STATUS_NONE                 0xFFFFFFFFU
#define SHM_STATUS_OK                   0U
#define SHM_STATUS_BAD_TYPE             1U
#define SHM_STATUS_BAD_SIZE             2U
#define SHM_STATUS_BAD_ADDRESS          3U
#define SHM_STATUS_NOT_READY            4U

//
// PING response payload: the first SHM_PING_QWORDS u64 values of Data.
// CR8 is sampled while serving (15 if and only if the handler ran at
// HIGH_LEVEL); the rest are handler-observed run counters, so one PING
// judges a whole session from user mode without touching the debugger.
//

#define SHM_PING_QWORDS                 5U
#define SHM_PING_CR8                    0U
#define SHM_PING_CYCLES                 1U
#define SHM_PING_ISSUES                 2U
#define SHM_PING_SERVED                 3U
#define SHM_PING_UP_TSC                 4U

//
// Bounds. One transfer never exceeds a page, so the NMI handler touches
// at most two physical frames per request. The mailbox holds the header
// plus one full message with room to spare.
//

#define SHM_MAX_TRANSFER                4096U
#define SHM_MAILBOX_BYTES               8192U

//
// Rendezvous. Kernel NT path (Zw routines) and the Win32 spelling of
// the same value (Reg APIs) for the consumer.
//

#define SHM_REG_KEY_PATH                L"\\Registry\\Machine\\SOFTWARE\\MmDiag"
#define SHM_REG_VALUE_NAME              L"Rendezvous"

// Consumer spelling: HKLM\SOFTWARE\MmDiag, value "Rendezvous", REG_BINARY.

//
// Highest physical byte the handler accepts. x64 implements at most 52
// physical address bits; anything wider would be truncated by the PTE
// frame mask and silently target the wrong page.
//

#define SHM_MAX_PHYSICAL                0x000FFFFFFFFFFFFFULL

/*++

Structure Description:

    The registry blob. Written by the consumer before driver load,
    consumed once by DriverEntry, then deleted. Every field is
    validated: Magic selects the structure, Size must equal
    SHM_MAILBOX_BYTES exactly, UserVa must be a user address without
    wraparound, and ProcessId must name a real, non-system process.

--*/

typedef struct _SHM_HANDSHAKE
{
    SHM_U64 Magic;
    SHM_U64 Nonce;
    SHM_U64 ProcessId;
    SHM_U64 UserVa;
    SHM_U64 Size;
} SHM_HANDSHAKE;

/*++

Structure Description:

    Mailbox header. Magic proves the mapping landed on the consumer's
    buffer rather than on recycled pages. Pending is the only flag the
    NMI stub tests: nonzero means a request is waiting. The consumer
    writes it last when submitting; the handler clears it last when
    completing. Its offset (8) is load bearing: the assembly stub tests
    [base+8] directly, pinned by a C_ASSERT on the kernel side.

--*/

typedef struct _SHM_HEADER
{
    SHM_U64 Magic;
    SHM_U32 Pending;
    SHM_U32 Reserved;
} SHM_HEADER;

/*++

Structure Description:

    One request/response. The consumer owns every field until it sets
    Pending; the handler owns Status and Data from service until it
    clears Pending. Seq is opaque to the kernel and echoed back so the
    consumer can pair answers. For PING the response Data carries
    SHM_PING_QWORDS u64 counters selected by SHM_PING_*: the CR8
    sampled at service time plus the run stats. For READ_PHYS the
    handler fills Data[0..Size); for WRITE_PHYS the consumer fills
    them.

--*/

typedef struct _SHM_MESSAGE
{
    SHM_U64 Magic;
    SHM_U64 Seq;
    SHM_U32 Type;
    SHM_U32 Status;
    SHM_U64 Phys;
    SHM_U32 Size;
    SHM_U32 Reserved;
    SHM_U8 Data[SHM_MAX_TRANSFER];
} SHM_MESSAGE;

/*++

Structure Description:

    The whole shared region: header followed by one message. Fits in
    SHM_MAILBOX_BYTES with headroom. The consumer allocates exactly
    this many bytes; the driver requires the handshake Size to match
    exactly.

--*/

typedef struct _SHM_MAILBOX
{
    SHM_HEADER Header;
    SHM_MESSAGE Message;
} SHM_MAILBOX;
