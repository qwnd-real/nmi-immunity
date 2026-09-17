#pragma once

#include <ntifs.h>

/*++

Module Name:

    Trace.h

Abstract:

    This module declares a bounded recorder for numeric observations made
    while the experiment owns processor state. Recording and printing are
    separate operations: a producer writes resident memory; the owner
    prints the buffer only after every producer has stopped.

    The buffer never wraps. Each reserved slot belongs to one invocation
    until that invocation publishes it. An NMI can interrupt a producer
    without waiting for its slot, and cannot overwrite a partially filled
    record. Full buffers and reservation collisions drop diagnostics. The
    caller must never use recording success as evidence about an NMI.

    Checked builds retain the recorder. Free builds discard each call and
    its argument evaluation through __noop, exactly like Debug.h.

--*/

//
// Capture the beginning of an experiment without allocating in a handler.
// Resetting or dumping requires producer quiescence. An indefinite worker
// will eventually exhaust this buffer; exhaustion affects diagnostics only.
//

#define KM_EVENT_CAPACITY                256
#define KM_EVENT_NO_VECTOR               MAXULONG

/*++

Enumeration Description:

    Observable milestones, used only for diagnosis. These values do not
    form the dispatch state machine and must not authorize a transition.

    IcrPostWrite means execution reached the marker following the APIC
    write. NmiEntry means vector 2 was entered. Neither observation proves
    which request caused delivery or whether another NMI remains pending.

    The coalescing race the dispatch tolerates:

        The self-NMI request is the ICR write in the APIC_WRITE section.
        Between that write and the processor's acceptance of the request,
        the delivery state is a single architectural latch, not a count.
        A foreign NMI raised inside that window merges with the self-NMI
        into one delivery. The handler's RIP-interval test identifies
        such a delivery as an expected self-NMI, consumes it, restores
        the native descriptor state and returns; if no second request
        stayed latched, the foreign event never reaches Windows.

        The rate is bounded, not eliminated: the window is the full
        self-NMI delivery latency (ICR completion to CPU acceptance),
        which makes the loss load-bearing rather than rare. NMIs carry
        no source identifier, so no observation inside the handler can
        distinguish that case. Experiments that require exact
        foreign-NMI accounting cannot use this scheme without a
        disarmed dwell W per cycle (see Apic.h): P = 1 - L/T.

        What the protocol never lets cross unowned is a loop issue: issues
        happen only at the loop top, every delivery is consumed in a stub,
        and the stop paths drain rather than terminate over a pending
        request. The single deliberate crosser is the synthetic answer to
        a consumed foreign (UnexpectedFault/vector 2 below): consumed
        natively right after the teardown's restore+iretq, where the
        sender's expecting NMI callback claims it -- or nothing does,
        which is NMI_HARDWARE_FAILURE and proves an unclaimed foreign.
        An UnexpectedFault record with vector 2 therefore marks a
        delivery the RIP test classified foreign; its NmiEntry sibling
        carries the interrupted RIP, so the window can be judged offline
        -- including postmortem from a crash dump, where an unclaimed
        crosser proves itself by the bugcheck that follows it.

    Detail is interpreted as follows:

        WorkerPinned          - Captured kernel CR3.
        NativeCaptured        - Address of the native-state snapshot.
        RestorePrepared       - Address of the prepared register block.
        CustomGdtLoaded       - Installed GDT base.
        CustomIdtLoaded       - Installed IDT base.
        ExpectedFault         - Architectural exception error code.
        IcrPostWrite          - Marker address for the active APIC mode.
        NmiEntry              - Interrupted RCX.
        NativeTablesRestored  - Restored IDT base.
        ReentryPrepared       - RCX to be restored by the return path.
        StopRequested         - Zero.
        UnexpectedFault       - Error code, or zero for vectors without one,
                                except vector 2: 0 marks a consumed foreign
                                answered with a synthetic, 1 marks an
                                expected drop (post-stash pre-Committed
                                prologue arrival consumed without a
                                synthetic -- bounded FN preferred over FP).

    Rip, Rsp and Cr8 describe the context being observed, supplied by the
    caller. For a trap, these are interrupted-context values, not values
    sampled after a C++ prologue. Vector is KM_EVENT_NO_VECTOR outside a
    trap. Record order is reservation order, which can differ from the
    order in which nested producers finish publishing their records.

--*/

typedef enum _KM_EVENT_ID
{
    KmEventWorkerPinned = 1,
    KmEventNativeCaptured,
    KmEventRestorePrepared,
    KmEventCustomGdtLoaded,
    KmEventCustomIdtLoaded,
    KmEventExpectedFault,
    KmEventIcrPostWrite,
    KmEventNmiEntry,
    KmEventNativeTablesRestored,
    KmEventReentryPrepared,
    KmEventStopRequested,
    KmEventUnexpectedFault
} KM_EVENT_ID;

/*++

Structure Description:

    One append-only observation. Published is written last with an
    interlocked operation, after every payload field has been assigned.
    A reserved record whose Published field is zero is incomplete; neither
    a debugger nor a dump routine should interpret its payload.

    All storage must remain resident and naturally aligned for the entire
    producer lifetime. The structure must never be placed in a packed
    containing structure or on a temporary setup stack.

--*/

typedef struct _KM_EVENT_RECORD
{
    LONG Published;
    KM_EVENT_ID Event;
    ULONG Vector;
    ULONG Reserved;
    ULONG64 Rip;
    ULONG64 Rsp;
    ULONG64 Cr8;
    ULONG64 Detail;
} KM_EVENT_RECORD, *PKM_EVENT_RECORD;

/*++

Structure Description:

    Storage owned by one pinned worker, including its nested trap paths.
    Initialization records the selected logical processor for later text
    output. The recorder does not enforce affinity or query processor state.

    NextRecord counts reservations, including any incomplete reservations.
    Dropped is a sticky flag: at least one record was lost to capacity or
    contention. It is deliberately not an unbounded event counter.

    The owner initializes this object before publishing it to producers,
    holds it until all producers have stopped, and serializes initialization
    and dumping with that lifetime. No live drain or concurrent reset is
    supported. Interlocked fields do not make a live payload read valid.

--*/

typedef struct _KM_EVENT_BUFFER
{
    LONG NextRecord;
    LONG Dropped;
    PROCESSOR_NUMBER Processor;
    KM_EVENT_RECORD Records[KM_EVENT_CAPACITY];
} KM_EVENT_BUFFER, *PKM_EVENT_BUFFER;

C_ASSERT((FIELD_OFFSET(KM_EVENT_RECORD, Published) % sizeof(LONG)) == 0);
C_ASSERT((FIELD_OFFSET(KM_EVENT_BUFFER, Records) % sizeof(ULONG64)) == 0);

#if DBG

_IRQL_requires_(PASSIVE_LEVEL)
VOID
KmEventInitialize(
    _Out_ PKM_EVENT_BUFFER Buffer,
    _In_ const PROCESSOR_NUMBER* Processor
);

//
// No allocation, formatting, waits, retry loops or kernel service calls.
// The assembly caller must provide a valid x64 ABI call frame, preserve the
// interrupted context and ensure the code, stack and buffer are resident.
// HIGH_LEVEL describes an IRQL ceiling; it does not prove those preconditions.
//

_IRQL_requires_max_(HIGH_LEVEL)
VOID
KmEventRecord(
    _Inout_ PKM_EVENT_BUFFER Buffer,
    _In_ KM_EVENT_ID Event,
    _In_ ULONG Vector,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Rsp,
    _In_ ULONG64 Cr8,
    _In_ ULONG64 Detail
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
KmEventDump(
    _In_ const KM_EVENT_BUFFER* Buffer
);

#else

#define KmEventInitialize(...) __noop(__VA_ARGS__)
#define KmEventRecord(...)     __noop(__VA_ARGS__)
#define KmEventDump(...)       __noop(__VA_ARGS__)

#endif

/*++

Module Name:

    Metric recorder (always on).

Abstract:

    One 64-byte record per NMI delivery, in a dedicated large buffer
    that never disturbs the 48-byte diagnostic buffer above. Each
    delivery reserves exactly one slot (reservation index == delivery
    Seq); a second reservation attempt on contention marks Dropped and
    invalidates any metric claim for the run (fail-closed). The assembly
    stub classifies first (transparent / in-window / dwell-foreign /
    expected-drop) and passes Rip/Rsp/Flags; the recorder fills Tsc
    (RDTSC at record time), Seq (reservation index), Cycle (sampled
    g_AsmCycleCount) and Issue (sampled g_AsmIssueSeq). Rip/Rsp describe
    the interrupted context; Flags is a bitmask below.

    KM_METRICS gates this path independently of DBG so free builds keep
    the metric while the text emitter stays PASSIVE_LEVEL-only.

--*/

#ifndef KM_METRICS
#define KM_METRICS 1
#endif

#define KM_METRIC_CAPACITY                16384

#define KM_METRIC_FLAG_STASH_UP           0x00000001UL
#define KM_METRIC_FLAG_IN_WINDOW          0x00000002UL
#define KM_METRIC_FLAG_IN_DWELL           0x00000004UL
#define KM_METRIC_FLAG_IN_DROP            0x00000008UL
#define KM_METRIC_FLAG_SYNTHETIC          0x00000010UL
#define KM_METRIC_FLAG_APICMODE_X2        0x00000020UL
#define KM_METRIC_FLAG_TRANSPARENT        0x00000040UL
#define KM_METRIC_FLAG_FOREIGN_PATH       0x00000080UL

typedef struct _KM_METRIC_RECORD
{
    LONG Published;
    ULONG Flags;
    ULONG Cpu;
    ULONG Reserved0;
    ULONG64 Tsc;
    ULONG64 Seq;
    ULONG64 Cycle;
    ULONG64 Issue;
    ULONG64 Rip;
    ULONG64 Rsp;
} KM_METRIC_RECORD, *PKM_METRIC_RECORD;

typedef struct _KM_METRIC_BUFFER
{
    LONG NextRecord;
    LONG Dropped;
    PROCESSOR_NUMBER Processor;
    ULONG64 UpTsc;
    ULONG64 StopSetTsc;
    ULONG64 ThreadExitTsc;
    KM_METRIC_RECORD Records[KM_METRIC_CAPACITY];
} KM_METRIC_BUFFER, *PKM_METRIC_BUFFER;

C_ASSERT((FIELD_OFFSET(KM_METRIC_RECORD, Published) % sizeof(LONG)) == 0);
C_ASSERT(sizeof(KM_METRIC_RECORD) == 64);
C_ASSERT((FIELD_OFFSET(KM_METRIC_BUFFER, Records) % sizeof(ULONG64)) == 0);

#if KM_METRICS

_IRQL_requires_(PASSIVE_LEVEL)
VOID
KmMetricInitialize(
    _Out_ PKM_METRIC_BUFFER Buffer,
    _In_ const PROCESSOR_NUMBER* Processor
);

//
// No allocation, formatting, waits, retry loops or kernel service calls.
// The assembly caller must provide a valid x64 ABI call frame, preserve the
// interrupted context and ensure the code, stack and buffer are resident.
// HIGH_LEVEL describes an IRQL ceiling; it does not prove those preconditions
// (and NMI itself runs above HIGH_LEVEL -- the ceiling is a static-analysis
// convention shared with KmEventRecord, not a proof of NMI preconditions).
// NMI-safe single-reservation append. Reads no MSRs, takes no locks,
// calls no kernel services: TSC + interlocked reservation + resident
// stores only. Never affects dispatch.
//

_IRQL_requires_max_(HIGH_LEVEL)
VOID
KmMetricRecord(
    _Inout_ PKM_METRIC_BUFFER Buffer,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Rsp,
    _In_ ULONG Flags
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
KmMetricDump(
    _In_ const KM_METRIC_BUFFER* Buffer
);

#else

#define KmMetricInitialize(...) __noop(__VA_ARGS__)
#define KmMetricRecord(...)     __noop(__VA_ARGS__)
#define KmMetricDump(...)       __noop(__VA_ARGS__)

#endif
