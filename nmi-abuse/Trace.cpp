#include "Trace.h"
#include "Asm.h"
#include "Debug.h"

/*++

Module Name:

    Trace.cpp

Abstract:

    This module implements the recorder declared in Trace.h. Producers
    reserve a slot with one compare-exchange attempt, assign scalar fields
    and publish with an interlocked store. There is no retry when a nested
    producer wins a reservation, and no reuse when the array fills.

    Reservation is separate from publication because an NMI or exception
    can interrupt a producer between any two instructions. A nested writer
    can reserve the next slot while the interrupted writer still owns its
    original slot. No producer waits for another producer to finish.

    Recording remains in the default resident code section. Initialization
    and dumping require PASSIVE_LEVEL, native descriptor state and exclusive
    lifecycle ownership of the buffer. A dump formats only published slots.

--*/

#if DBG

//
// Forward declarations for internal helper functions
//

static
PCSTR
KmEventToString(
    _In_ KM_EVENT_ID Event
);

_Use_decl_annotations_
VOID
KmEventInitialize(
    PKM_EVENT_BUFFER Buffer,
    const PROCESSOR_NUMBER* Processor
)
/*++

Routine Description:

    Initializes all records before the owner makes the buffer reachable by
    a producer. Reinitialization is allowed only after producer quiescence.
    Processor must not alias storage inside Buffer, which is cleared first.

Arguments:

    Buffer - Caller-owned, naturally aligned, resident recording storage.

    Processor - Logical processor selected for the owning worker. The
        pointed-to value is copied and need not outlive this call.

Return Value:

    None.

--*/
{
    RtlZeroMemory(Buffer, sizeof(*Buffer));
    Buffer->Processor = *Processor;
}

_Use_decl_annotations_
VOID
KmEventRecord(
    PKM_EVENT_BUFFER Buffer,
    KM_EVENT_ID Event,
    ULONG Vector,
    ULONG64 Rip,
    ULONG64 Rsp,
    ULONG64 Cr8,
    ULONG64 Detail
)
/*++

Routine Description:

    Attempts one bounded append. Failure is deliberately unobservable to
    dispatch code: recording cannot become a condition for restoring state,
    forwarding an event, retrying an APIC write or returning from a trap.

    The first interlocked operation reads the reservation cursor. The second
    attempts to claim that exact slot. If an interrupting producer changed
    the cursor between them, this invocation marks the buffer as lossy and
    returns. It never waits for the interrupting producer or retries a slot.

Arguments:

    Buffer - Initialized storage whose lifetime covers all producers.

    Event - Observed milestone, without any implied NMI source identity.

    Vector - Architectural vector, or KM_EVENT_NO_VECTOR outside a trap.

    Rip - Instruction pointer of the context being observed.

    Rsp - Stack pointer of that context.

    Cr8 - CR8 value associated with that context.

    Detail - Event-specific value described beside KM_EVENT_ID in Trace.h.

Return Value:

    None. Dropped diagnostics set Buffer->Dropped and change no control flow
    outside this routine. In particular, no text emitter is called on loss.

--*/
{
    LONG Index;
    PKM_EVENT_RECORD Record;

    Index = InterlockedCompareExchange(&Buffer->NextRecord, 0, 0);

    if ((ULONG)Index >= KM_EVENT_CAPACITY)
    {
        (VOID)InterlockedExchange(&Buffer->Dropped, 1);
        return;
    }

    if (InterlockedCompareExchange(&Buffer->NextRecord, Index + 1, Index) != Index)
    {
        (VOID)InterlockedExchange(&Buffer->Dropped, 1);
        return;
    }

    Record = &Buffer->Records[Index];
    Record->Event = Event;
    Record->Vector = Vector;
    Record->Rip = Rip;
    Record->Rsp = Rsp;
    Record->Cr8 = Cr8;
    Record->Detail = Detail;

    //
    // Publication is the final write. Slots are never reused, so a nested
    // producer cannot replace this payload while it is being constructed.
    // A fatal interruption can leave Published clear for dump inspection.
    //

    (VOID)InterlockedExchange(&Record->Published, 1);
}

static
PCSTR
KmEventToString(
    _In_ KM_EVENT_ID Event
)
/*++

Routine Description:

    Translates an observation identifier while dumping a stopped buffer.
    Producers store identifiers only and never call this routine.

Arguments:

    Event - Observation identifier stored in a published record.

Return Value:

    A static, never NULL, string. Unknown values remain visible numerically
    in the caller's output.

--*/
{
    switch (Event)
    {
    case KmEventWorkerPinned:         return "WorkerPinned";
    case KmEventNativeCaptured:       return "NativeCaptured";
    case KmEventRestorePrepared:      return "RestorePrepared";
    case KmEventCustomGdtLoaded:      return "CustomGdtLoaded";
    case KmEventCustomIdtLoaded:      return "CustomIdtLoaded";
    case KmEventExpectedFault:        return "ExpectedFault";
    case KmEventIcrPostWrite:         return "IcrPostWrite";
    case KmEventNmiEntry:             return "NmiEntry";
    case KmEventNativeTablesRestored: return "NativeTablesRestored";
    case KmEventReentryPrepared:      return "ReentryPrepared";
    case KmEventStopRequested:        return "StopRequested";
    case KmEventUnexpectedFault:      return "UnexpectedFault";
    default:                        return "Event?";
    }
}

_Use_decl_annotations_
VOID
KmEventDump(
    const KM_EVENT_BUFFER* Buffer
)
/*++

Routine Description:

    Prints a stopped buffer through Debug.h. The owner must establish that
    no thread, exception handler or NMI handler can still access the buffer
    before calling. Reading a count or restoring IDTR alone does not prove
    that a producer interrupted before publication has finished.

    Dumping does not reset the array. A later reset is a separate lifecycle
    operation with the same producer-quiescence requirement.

Arguments:

    Buffer - Initialized recording storage with all producers stopped.

Return Value:

    None. A malformed count is logged and rejected without reading records.

--*/
{
    ULONG Count;
    ULONG Index;
    const KM_EVENT_RECORD* Record;

    Count = (ULONG)Buffer->NextRecord;

    if (Count > KM_EVENT_CAPACITY)
    {
        KmError("Invalid event buffer - Reservations=%u Capacity=%u\n",
            Count, KM_EVENT_CAPACITY);
        return;
    }

    KmPrint("Event buffer - Processor=%u:%u Reservations=%u Dropped=%ld\n",
        (ULONG)Buffer->Processor.Group, (ULONG)Buffer->Processor.Number,
        Count, Buffer->Dropped);

    for (Index = 0; Index < Count; Index += 1)
    {
        Record = &Buffer->Records[Index];

        if (Record->Published == 0)
        {
            KmWarning("Event[%u] - Reserved but not published\n", Index);
            continue;
        }

        KmTrace("Event[%u] - Name=%s Id=%u Vector=0x%08X "
            "Rip=0x%016I64X Rsp=0x%016I64X Cr8=0x%I64X Detail=0x%016I64X\n",
            Index, KmEventToString(Record->Event), (ULONG)Record->Event,
            Record->Vector, Record->Rip, Record->Rsp, Record->Cr8, Record->Detail);
    }

    if (Buffer->Dropped != 0)
    {
        KmWarning("Event history is incomplete - Capacity or reservation contention\n");
    }
}

#endif

//
// Unconditionally resident: the assembly stubs call this in every
// build. In retail KmEventRecord compiles away and this is empty.
//

EXTERN_C_START

_Use_decl_annotations_
VOID
AsmRecordEvent(
    PVOID Buffer,
    ULONG Event,
    ULONG Vector,
    ULONG64 Rip,
    ULONG64 Rsp,
    ULONG64 Cr8,
    ULONG64 Detail
)
/*++

Routine Description:

    Unmangled forwarder over KmEventRecord for the assembly stubs,
    which cannot call a C++-mangled name. Same contract: one bounded
    append attempt, lossy by design, never affects dispatch. In retail
    the inner call compiles away and this is an empty resident stub.

Arguments:

    Buffer - May be NULL, in which case nothing is recorded. The
        assembly paths test this first and skip the call.

    Event - Numeric milestone; kept ULONG so the assembler never has
        to know the enum. Values are pinned by the C_ASSERTs below.

    Vector - Architectural vector, or KM_EVENT_NO_VECTOR.

    Rip - Interrupted RIP, read from the trap frame.

    Rsp - Interrupted RSP, read from the trap frame.

    Cr8 - CR8 sampled on entry.

    Detail - Event-specific value per Trace.h.

Return Value:

    None.

--*/
{
    if (Buffer == NULL)
    {
        return;
    }

    KmEventRecord(
        (PKM_EVENT_BUFFER)Buffer,
        (KM_EVENT_ID)Event,
        Vector,
        Rip,
        Rsp,
        Cr8,
        Detail
    );
}

EXTERN_C_END

//
// Pin the numeric milestones the assembly file hardcodes as
// immediates. If Trace.h renumbers, this fails the build instead of
// silently mislabeling the event history.
//

C_ASSERT(KmEventExpectedFault == 6);
C_ASSERT(KmEventIcrPostWrite == 7);
C_ASSERT(KmEventNmiEntry == 8);
C_ASSERT(KmEventNativeTablesRestored == 9);
C_ASSERT(KmEventUnexpectedFault == 12);

//
// Pin the recorder layout the assembly paths assume only implicitly:
// they never touch these offsets (all recording goes through the
// forwarder above), but the no-page-fault argument depends on the
// buffer living in resident non-paged pool, which the worker's static
// allocation provides.
//

C_ASSERT(sizeof(KM_EVENT_RECORD) == 48);
C_ASSERT(FIELD_OFFSET(KM_EVENT_RECORD, Detail) == 40);
