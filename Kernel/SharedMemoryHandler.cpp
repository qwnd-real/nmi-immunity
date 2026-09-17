#include "SharedMemoryHandler.h"
#include "Physical.h"
#include "Asm.h"
#include "Debug.h"

#include <intrin.h>

/*++

Module Name:

    SharedMemoryHandler.cpp

Abstract:

    This module implements the mailbox declared in
    SharedMemoryHandler.h.

    The PASSIVE_LEVEL half (PAGE section) consumes the rendezvous blob
    once in DriverEntry: it opens the key, validates every field of the
    blob, resolves the process, attaches to it, MDL-locks the
    consumer's buffer with user-mode probing, maps the locked frames
    into system space and publishes the mapping for the NMI side. The
    blob is then deleted, so a reload without a fresh consumer fails
    loudly instead of re-locking stale addresses.

    The HIGH_LEVEL half (resident section) is ShmHandleRequest, called
    from the NMI stub with the mailbox address. It snapshots the
    message, validates the snapshot, serves PING/READ_PHYS/WRITE_PHYS
    through the Physical window and completes the request. See the IRQL
    contract in the header: allowlisted calls only, bounded work only.

--*/

//
// Lifetime state. Static non-paged storage: the NMI side reads the
// mailbox address and the ready flag at HIGH_LEVEL. The mailbox pages
// themselves stay resident because the MDL holds them locked from
// handshake to teardown. Publication order is mailbox fields, then the
// assembly base, then ready, each separated by a barrier; teardown
// runs the same order in reverse after the worker has stopped, so no
// NMI can be in flight while anything below is released.
//

static PVOID g_ShmMailboxVa = NULL;
static PMDL g_ShmMdl = NULL;
static SIZE_T g_ShmSize = 0;
static HANDLE g_ShmPid = NULL;
static volatile BOOLEAN g_ShmReady = FALSE;

//
// Completed requests, every status counted. Read by the PING payload
// and by nobody else; the NMI side owns the only writer while
// interrupts are disabled, and the interlocked op keeps the rare
// same-CPU nesting honest.
//

static volatile LONG64 g_ShmServed = 0;

//
// Pin the layout facts the assembly stub and the handler rely on:
// Pending lives at mailbox offset 8 (the stub tests [base+8]), the
// PING payload stays 8-byte aligned, and one mailbox fits the
// consumer's allocation contract.
//

C_ASSERT(FIELD_OFFSET(SHM_MAILBOX, Header.Pending) == 8);
C_ASSERT((FIELD_OFFSET(SHM_MESSAGE, Data) % sizeof(SHM_U64)) == 0);
C_ASSERT(sizeof(SHM_MAILBOX) <= SHM_MAILBOX_BYTES);
C_ASSERT(sizeof(SHM_HANDSHAKE) == 40);

#pragma code_seg(push)
#pragma code_seg("PAGE")

static
VOID
ShmDropMapping(
    VOID
)
/*++

Routine Description:

    Releases a published mapping: unpublish first (barriers, so an
    in-flight observer sees the teardown), then unmap, unlock and free
    the MDL. Operates on the globals only; the handshake's locals are
    handled inline at their own failure sites. Safe to call with
    nothing published.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    g_ShmReady = FALSE;
    KeMemoryBarrier();

    g_AsmShmBase = 0;
    KeMemoryBarrier();

    if (g_ShmMailboxVa != NULL && g_ShmMdl != NULL)
    {
        MmUnmapLockedPages(g_ShmMailboxVa, g_ShmMdl);
        g_ShmMailboxVa = NULL;
    }

    if (g_ShmMdl != NULL)
    {
        MmUnlockPages(g_ShmMdl);
        IoFreeMdl(g_ShmMdl);
        g_ShmMdl = NULL;
    }

    g_ShmSize = 0;
    g_ShmPid = NULL;
}

_Use_decl_annotations_
NTSTATUS
ShmHandshake(
    VOID
)
/*++

Routine Description:

    Consumes the rendezvous blob and publishes the mailbox. Runs once
    in DriverEntry, in the loading thread, before the worker is born:
    the first NMI delivery may already find a request pending, so the
    Physical window must already be initialized by the caller and the
    mailbox base must be published before this returns success.

    The blob must be present and exact: absent key or value fails the
    load (the mailbox is mandatory, a silent no-mailbox boot would
    leave the consumer polling forever), and any malformed field fails
    it too. The value is deleted on success so a stale blob can never
    be consumed twice.

Arguments:

    None.

Return Value:

    STATUS_SUCCESS with the mailbox locked, mapped and published, and
    the rendezvous value deleted.

    STATUS_OBJECT_NAME_NOT_FOUND when the key or the value is absent.

    STATUS_INVALID_PARAMETER for a malformed blob (bad magic, wrong
    size, null or kernel address, wraparound, system PID).

    The process lookup or lock status for failures in those steps.

--*/
{
    UNICODE_STRING KeyPath;
    UNICODE_STRING ValueName;
    OBJECT_ATTRIBUTES Attributes;
    HANDLE KeyHandle;
    UCHAR ValueBuffer[FIELD_OFFSET(KEY_VALUE_PARTIAL_INFORMATION, Data) +
        sizeof(SHM_HANDSHAKE)];
    PKEY_VALUE_PARTIAL_INFORMATION ValueInfo;
    SHM_HANDSHAKE* Blob;
    ULONG ReturnedLength;
    PEPROCESS Process;
    KAPC_STATE ApcState;
    PMDL Mdl;
    PVOID SystemVa;
    volatile SHM_MAILBOX* Mailbox;
    NTSTATUS Status;

    PAGED_CODE();

    g_ShmMailboxVa = NULL;
    g_ShmMdl = NULL;
    g_ShmSize = 0;
    g_ShmPid = NULL;
    g_ShmReady = FALSE;

    RtlInitUnicodeString(&KeyPath, SHM_REG_KEY_PATH);
    RtlInitUnicodeString(&ValueName, SHM_REG_VALUE_NAME);
    InitializeObjectAttributes(
        &Attributes,
        &KeyPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    Status = ZwOpenKey(
        &KeyHandle,
        KEY_QUERY_VALUE | KEY_SET_VALUE,
        &Attributes
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Rendezvous key absent - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        return Status;
    }

    RtlZeroMemory(ValueBuffer, sizeof(ValueBuffer));
    ReturnedLength = 0;

    Status = ZwQueryValueKey(
        KeyHandle,
        &ValueName,
        KeyValuePartialInformation,
        ValueBuffer,
        sizeof(ValueBuffer),
        &ReturnedLength
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Rendezvous value unreadable - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        ZwClose(KeyHandle);
        return Status;
    }

    ValueInfo = (PKEY_VALUE_PARTIAL_INFORMATION)ValueBuffer;

    if ((ValueInfo->Type != REG_BINARY) ||
        (ValueInfo->DataLength != sizeof(SHM_HANDSHAKE)) ||
        (ReturnedLength != sizeof(ValueBuffer)))
    {
        KmError("Rendezvous value malformed - Type=%u Length=%u\n",
            ValueInfo->Type, ValueInfo->DataLength);
        ZwClose(KeyHandle);
        return STATUS_INVALID_PARAMETER;
    }

    Blob = (SHM_HANDSHAKE*)ValueInfo->Data;

    if (Blob->Magic != SHM_MAGIC_HANDSHAKE)
    {
        KmError("Rendezvous magic mismatch - 0x%I64X\n", Blob->Magic);
        ZwClose(KeyHandle);
        return STATUS_INVALID_PARAMETER;
    }

    if (Blob->Size != SHM_MAILBOX_BYTES)
    {
        KmError("Rendezvous size mismatch - Size=%I64u Expected=%u\n",
            Blob->Size, SHM_MAILBOX_BYTES);
        ZwClose(KeyHandle);
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Null and wraparound are rejected here. Kernel-range addresses
    // are rejected at the point of use by the UserMode probe below,
    // which is the authority on what user space means on this boot:
    // no MmHighestUserAddress dependency, no LA57 special case.
    //

    if ((Blob->UserVa == 0) ||
        ((Blob->UserVa + Blob->Size) < Blob->UserVa))
    {
        KmError("Rendezvous address invalid - Va=0x%I64X Size=%I64u\n",
            Blob->UserVa, Blob->Size);
        ZwClose(KeyHandle);
        return STATUS_INVALID_PARAMETER;
    }

    if ((Blob->ProcessId == 0) || (Blob->ProcessId <= 4))
    {
        KmError("Rendezvous process invalid - Pid=%I64u\n",
            Blob->ProcessId);
        ZwClose(KeyHandle);
        return STATUS_INVALID_PARAMETER;
    }

    Status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)Blob->ProcessId,
        &Process
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Rendezvous process unresolvable - Pid=%I64u Status=%s "
            "(0x%08X)\n",
            Blob->ProcessId, KmStatusToString(Status), Status);
        ZwClose(KeyHandle);
        return Status;
    }

    //
    // Lock and map inside the consumer's address space. Probing as
    // user mode rejects kernel addresses a second time, at the point
    // of use rather than at the point of parsing.
    //

    Mdl = NULL;
    SystemVa = NULL;
    Status = STATUS_SUCCESS;

    KeStackAttachProcess((PRKPROCESS)Process, &ApcState);

    __try
    {
        Mdl = IoAllocateMdl(
            (PVOID)(ULONG_PTR)Blob->UserVa,
            (ULONG)Blob->Size,
            FALSE,
            FALSE,
            NULL
        );

        if (Mdl == NULL)
        {
            KmError("Mailbox MDL allocation failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        //
        // __leave inside the handler below only exits the inner probe;
        // the explicit status check is what leaves the outer attach
        // block (through its __finally detach). A bare __leave in an
        // __except body would fall through into the mapper with a
        // NULL MDL.
        //

        {
            NTSTATUS LockStatus;

            __try
            {
                MmProbeAndLockPages(Mdl, UserMode, IoModifyAccess);
                LockStatus = STATUS_SUCCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                LockStatus = GetExceptionCode();
            }

            if (!NT_SUCCESS(LockStatus))
            {
                KmError("Mailbox lock failed - Status=%s (0x%08X)\n",
                    KmStatusToString(LockStatus), LockStatus);
                IoFreeMdl(Mdl);
                Mdl = NULL;
                Status = LockStatus;
                __leave;
            }
        }

        SystemVa = MmGetSystemAddressForMdlSafe(Mdl, NormalPagePriority);

        if (SystemVa == NULL)
        {
            KmError("Mailbox system mapping failed\n");
            Status = STATUS_INSUFFICIENT_RESOURCES;
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            Mdl = NULL;
            __leave;
        }

        Mailbox = (volatile SHM_MAILBOX*)SystemVa;

        if (Mailbox->Header.Magic != SHM_MAGIC_MAILBOX)
        {
            KmError("Mailbox header magic mismatch - 0x%I64X\n",
                Mailbox->Header.Magic);
            Status = STATUS_INVALID_PARAMETER;
            MmUnmapLockedPages(SystemVa, Mdl);
            SystemVa = NULL;
            MmUnlockPages(Mdl);
            IoFreeMdl(Mdl);
            Mdl = NULL;
            __leave;
        }

        //
        // Publish: mapping fields, then the assembly base the NMI
        // stub tests, then ready, each separated by a barrier. The
        // stub observes either a fully published mailbox or nothing.
        //

        g_ShmMdl = Mdl;
        g_ShmMailboxVa = SystemVa;
        g_ShmSize = (SIZE_T)Blob->Size;
        g_ShmPid = (HANDLE)(ULONG_PTR)Blob->ProcessId;
        KeMemoryBarrier();

        g_AsmShmBase = (ULONG64)(ULONG_PTR)SystemVa;
        KeMemoryBarrier();

        g_ShmReady = TRUE;
        KeMemoryBarrier();

        //
        // Answer the handshake through the mapping itself: the
        // consumer polls Status for something other than NONE with
        // its Nonce in Seq. Pending stays zero, so an NMI landing
        // right here observes an idle mailbox.
        //

        Mailbox->Message.Status = SHM_STATUS_OK;
        KeMemoryBarrier();
    }
    __finally
    {
        KeUnstackDetachProcess(&ApcState);
    }

    ObDereferenceObject(Process);

    if (!NT_SUCCESS(Status))
    {
        ZwClose(KeyHandle);
        return Status;
    }

    //
    // Consume the blob: a stale rendezvous must never survive into a
    // later load. Deletion failure unwinds the whole mapping rather
    // than leaving a live mailbox behind an unconsumed blob.
    //

    Status = ZwDeleteValueKey(KeyHandle, &ValueName);
    ZwClose(KeyHandle);

    if (!NT_SUCCESS(Status))
    {
        KmError("Rendezvous delete failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        ShmDropMapping();
        return Status;
    }

    KmPrint("Mailbox ready - Pid=%I64u Va=0x%I64X Size=%I64u Nonce=0x%I64X\n",
        Blob->ProcessId, Blob->UserVa, Blob->Size, Blob->Nonce);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ShmUninitialize(
    VOID
)
/*++

Routine Description:

    Drops the published mapping, if any. Runs after the worker has
    stopped, so no NMI can observe the teardown halfway: the base the
    stub tests is cleared before anything it points to is released.
    Safe to call without a prior handshake.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    ShmDropMapping();

    KmTrace("Mailbox released\n");
}

#pragma code_seg(pop)

//
// HIGH_LEVEL SECTION. Everything below runs inside the NMI handler.
// See the IRQL contract in SharedMemoryHandler.h: allowlisted calls
// only (PhysicalSetBacking, PhysicalGetWindow, RtlCopyMemory,
// KeMemoryBarrier, compiler intrinsics), bounded work only, no
// logging, no services, no exceptions.
//

EXTERN_C_START

_Use_decl_annotations_
VOID
ShmHandleRequest(
    PVOID Mailbox
)
/*++

Routine Description:

    Services one pending mailbox request at HIGH_LEVEL. The message is
    snapshotted once into locals and never re-read: the consumer may
    race its own submission, but a racing consumer can only corrupt
    its own answer, never the box. Every field is validated from the
    snapshot before use; anything malformed completes with an error
    status rather than stalling the channel.

    PING answers with the CR8 sampled at service time, which is 15 if
    and only if this ran at HIGH_LEVEL, plus the run counters selected
    by SHM_PING_*. READ_PHYS and WRITE_PHYS move at most
    SHM_MAX_TRANSFER bytes through the Physical window, one frame per
    backing switch. Status is written before Pending is cleared, each
    separated by a barrier, so the consumer either sees a complete
    answer or a still-pending request.

Arguments:

    Mailbox - The published mailbox address, passed by the NMI stub,
        which guarantees CR8 == 15 before calling.

Return Value:

    None. Results travel in the mailbox, never in a return value.

--*/
{
    volatile SHM_MAILBOX* Box;
    SHM_U64 MessageMagic;
    SHM_U32 Type;
    SHM_U64 Phys;
    SHM_U32 Size;
    SHM_U32 Status;
    SHM_U64 Served;
    PVOID Window;

    if (Mailbox == NULL)
    {
        return;
    }

    if (!g_ShmReady)
    {
        return;
    }

    Box = (volatile SHM_MAILBOX*)Mailbox;

    if (Box->Header.Magic != SHM_MAGIC_MAILBOX)
    {
        return;
    }

    if (Box->Header.Pending == 0)
    {
        return;
    }

    KeMemoryBarrier();

    //
    // Snapshot everything validated below. Past this point the
    // consumer's bytes are payload, never control.
    //

    MessageMagic = Box->Message.Magic;
    Type = Box->Message.Type;
    Phys = Box->Message.Phys;
    Size = Box->Message.Size;

    Status = SHM_STATUS_OK;

    if (MessageMagic != SHM_MAGIC_MESSAGE)
    {
        Status = SHM_STATUS_BAD_TYPE;
        goto Complete;
    }

    if ((Type != SHM_REQ_PING) &&
        (Type != SHM_REQ_READ_PHYS) &&
        (Type != SHM_REQ_WRITE_PHYS))
    {
        Status = SHM_STATUS_BAD_TYPE;
        goto Complete;
    }

    if ((Type != SHM_REQ_PING) && (Size > SHM_MAX_TRANSFER))
    {
        Status = SHM_STATUS_BAD_SIZE;
        goto Complete;
    }

    if ((Type != SHM_REQ_PING) && (Size > 0))
    {
        //
        // The frame mask keeps 52 physical bits. Anything wider
        // would be truncated into the wrong page, so it fails here
        // instead. The addition cannot wrap past the check: a wrap
        // makes the end smaller than the start, which the mask test
        // then rejects as out of range.
        //

        if (((Phys + (SHM_U64)Size - 1) & ~SHM_MAX_PHYSICAL) != 0)
        {
            Status = SHM_STATUS_BAD_ADDRESS;
            goto Complete;
        }
    }

    Window = PhysicalGetWindow();

    if ((Type != SHM_REQ_PING) && (Window == NULL))
    {
        Status = SHM_STATUS_NOT_READY;
        goto Complete;
    }

    if (Type == SHM_REQ_READ_PHYS)
    {
        PUCHAR Destination;
        SHM_U64 Current;
        SHM_U32 Remaining;

        Destination = (PUCHAR)Box->Message.Data;
        Current = Phys;
        Remaining = Size;

        while (Remaining > 0)
        {
            SIZE_T Offset;
            SIZE_T Chunk;

            Offset = (SIZE_T)(Current & 0xFFFULL);
            Chunk = PAGE_SIZE - Offset;

            if (Chunk > (SIZE_T)Remaining)
            {
                Chunk = (SIZE_T)Remaining;
            }

            PhysicalSetBacking(Current & ~0xFFFULL);

            RtlCopyMemory(
                Destination,
                (PUCHAR)Window + Offset,
                Chunk
            );

            Destination += Chunk;
            Current += Chunk;
            Remaining -= (SHM_U32)Chunk;
        }
    }
    else if (Type == SHM_REQ_WRITE_PHYS)
    {
        PCUCHAR Source;
        SHM_U64 Current;
        SHM_U32 Remaining;

        Source = (PCUCHAR)Box->Message.Data;
        Current = Phys;
        Remaining = Size;

        while (Remaining > 0)
        {
            SIZE_T Offset;
            SIZE_T Chunk;

            Offset = (SIZE_T)(Current & 0xFFFULL);
            Chunk = PAGE_SIZE - Offset;

            if (Chunk > (SIZE_T)Remaining)
            {
                Chunk = (SIZE_T)Remaining;
            }

            PhysicalSetBacking(Current & ~0xFFFULL);

            RtlCopyMemory(
                (PUCHAR)Window + Offset,
                Source,
                Chunk
            );

            Source += Chunk;
            Current += Chunk;
            Remaining -= (SHM_U32)Chunk;
        }
    }

Complete:

    //
    // Every completion counts, whatever the status: the counter is
    // the handler's own activity record. The PING payload is composed
    // here, after the count, so the served value includes the request
    // being answered. The assembly-owned counters are sampled with
    // the same interlocked read Trace.cpp uses: aligned 8-byte loads
    // that disturb nothing at HIGH_LEVEL.
    //

    Served = (SHM_U64)InterlockedIncrement64(&g_ShmServed);

    if ((Status == SHM_STATUS_OK) && (Type == SHM_REQ_PING))
    {
        volatile SHM_U64* Payload;

        Payload = (volatile SHM_U64*)Box->Message.Data;
        Payload[SHM_PING_CR8] = (SHM_U64)__readcr8();
        Payload[SHM_PING_CYCLES] = (SHM_U64)InterlockedCompareExchange64(
            (LONG64 volatile*)&g_AsmCycleCount, 0, 0);
        Payload[SHM_PING_ISSUES] = (SHM_U64)InterlockedCompareExchange64(
            (LONG64 volatile*)&g_AsmIssueSeq, 0, 0);
        Payload[SHM_PING_SERVED] = Served;
        Payload[SHM_PING_UP_TSC] = (SHM_U64)InterlockedCompareExchange64(
            (LONG64 volatile*)&g_AsmUpTsc, 0, 0);
    }

    KeMemoryBarrier();
    Box->Message.Status = Status;
    KeMemoryBarrier();
    Box->Header.Pending = 0;
    KeMemoryBarrier();
}

EXTERN_C_END
