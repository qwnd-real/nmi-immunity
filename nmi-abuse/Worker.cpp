#include "Worker.h"
#include "Apic.h"
#include "Tables.h"
#include "Asm.h"
#include "Trace.h"
#include "Debug.h"

#include <intrin.h>

/*++

Module Name:

    Worker.cpp

Abstract:

    Implements Worker.h. All of it runs on the loading thread: it pins
    itself to the target CPU, detects the APIC mode, captures that CPU's
    native descriptor state, publishes everything to the assembly
    protocol and then creates the experiment thread born inside the
    gadget. The experiment thread itself never runs a byte of this file.

--*/

#if defined(_AMD64_)

//
// Lifetime state. All of it is static non-paged storage: the assembly
// paths dereference the buffer and the stop flag while the custom IDT
// is loaded, where paged memory would be fatal rather than faultable.
//

static HANDLE g_WorkerThreadHandle = NULL;
static PETHREAD g_WorkerThreadObject = NULL;
static LONG volatile g_WorkerStopFlag = 0;
static KM_EVENT_BUFFER g_WorkerEvents;
static APIC_STATE g_WorkerApic;
static TABLES_STATE g_WorkerTables;
static RESTORE_TARGET g_WorkerTarget;
static PROCESSOR_NUMBER g_WorkerProcessor;
static BOOLEAN g_WorkerRunning = FALSE;

//
// Group-0-only pinning (see WorkerStart): one mask bit.
//

static KAFFINITY g_WorkerAffinityMask = 0;

//
// ZwQueryInformationThread. Exported by ntoskrnl for the affinity
// read-back, but not declared in the driver headers, so the prototype
// is mirrored here the way KmModule.cpp mirrors its query.
//

EXTERN_C_START

NTKERNELAPI
NTSTATUS
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C_END

//
// First-cycle proof poll: how long to wait for the #GP stub's stash,
// and the sleep between polls.
//

#define WORKER_PROOF_TIMEOUT_MS         30000
#define WORKER_PROOF_POLL_MS            10

//
// Forward declarations for internal helper functions
//

static
VOID
WorkerFillAsmState(
    _In_ const PROCESSOR_NUMBER* Processor
);

static
VOID
WorkerRecordSetup(
    _In_ const PROCESSOR_NUMBER* Processor
);

static
VOID
WorkerWaitForFirstCycle(
    VOID
);

static
VOID
WorkerFillAsmState(
    _In_ const PROCESSOR_NUMBER* Processor
)
/*++

Routine Description:

    Points the assembly protocol at this CPU's state. Runs pinned, at
    PASSIVE_LEVEL with native tables, before thread creation.

Arguments:

    Processor - The pinned processor, for the event header.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(Processor);

    g_AsmApicMode = g_WorkerApic.Mode;
    g_AsmXapicIcrLow = (ULONG64)(ULONG_PTR)g_WorkerApic.IcrLow;
    g_AsmXapicIcrHigh = (ULONG64)(ULONG_PTR)g_WorkerApic.IcrHigh;
    g_AsmNativeGdtrLimit = g_WorkerTables.NativeLimit;
    g_AsmNativeGdtrBase = g_WorkerTables.NativeGdtBase;
    g_AsmNativeIdtrLimit = g_WorkerTables.NativeIdtLimit;
    g_AsmNativeIdtrBase = g_WorkerTables.NativeIdtBase;
    g_AsmNativeCs = g_WorkerTables.NativeCs;
    g_AsmNativeSs = g_WorkerTables.NativeSs;
    g_AsmEventBuffer = (ULONG64)(ULONG_PTR)&g_WorkerEvents;
    g_AsmStopFlag = &g_WorkerStopFlag;
    g_AsmBlock = (ULONG64)(ULONG_PTR)g_WorkerTables.Block;
    g_AsmRoutine = g_WorkerTarget.RoutineAddress;
    g_AsmEntryRsp = 0;
    g_AsmCycleCount = 0;

    KeMemoryBarrier();
}

static
VOID
WorkerRecordSetup(
    _In_ const PROCESSOR_NUMBER* Processor
)
/*++

Routine Description:

    Opens the event history with the three setup observations. Runs
    pinned, before thread creation, so the interrupted-context fields
    carry the pristine native state the first cycle starts from.

Arguments:

    Processor - The pinned processor, for the event header.

Return Value:

    None.

--*/
{
    KmEventInitialize(&g_WorkerEvents, Processor);

    KmEventRecord(
        &g_WorkerEvents,
        KmEventWorkerPinned,
        KM_EVENT_NO_VECTOR,
        g_WorkerTarget.RoutineAddress,
        (ULONG64)(ULONG_PTR)g_WorkerTables.Block,
        (ULONG64)__readcr8(),
        (ULONG64)__readcr3()
    );

    KmEventRecord(
        &g_WorkerEvents,
        KmEventNativeCaptured,
        KM_EVENT_NO_VECTOR,
        g_WorkerTables.NativeIdtBase,
        g_WorkerTables.NativeGdtBase,
        (ULONG64)g_WorkerTables.NativeCs,
        (ULONG64)(ULONG_PTR)&g_WorkerTables
    );

    KmEventRecord(
        &g_WorkerEvents,
        KmEventRestorePrepared,
        KM_EVENT_NO_VECTOR,
        g_WorkerTarget.RoutineAddress,
        (ULONG64)(ULONG_PTR)g_WorkerTables.Block,
        TABLES_CR8_BLOCK_ALL,
        (ULONG64)(ULONG_PTR)g_WorkerTables.Idt
    );
}

/*++

    PAGEABLE LIFECYCLE SECTION

--*/

#pragma code_seg(push)
#pragma code_seg("PAGE")

_Use_decl_annotations_
NTSTATUS
WorkerStart(
    const RESTORE_TARGET* Target
)
/*++

Routine Description:

    Starts the experiment: pins the current thread to the target CPU,
    detects the APIC mode, captures that CPU's native descriptor state,
    publishes everything to the assembly protocol and creates the system
    thread born inside the gadget.

    Birth contract: StartRoutine is the resolved gadget address and
    StartContext is the prepared block. x64 thread startup calls
    StartRoutine(StartContext), so the thread's first instruction is the
    gadget's with RCX already holding the block. No wrapper runs on it.

    Pinning: the setup captures the executing CPU, so it runs pinned to
    the target; the new thread is pinned to the same CPU with
    KeSetAffinityThread immediately after creation. Both use group 0
    (single-group machines, the test target); a first-processor group
    above zero fails load rather than preparing state for the wrong CPU.

    Proof: after unpinning, the start polls the #GP stub's entry-RSP
    stash. A nonzero stash proves the thread reached the expected fault
    and entered the window: the experiment is cycling. The gadget is a
    straight line to the faulting LTR, so a healthy thread proves
    within milliseconds; the timeout only fires when the branch
    assumption was wrong or the machine wedged.

    Load note, stated plainly: while cycling, the pinned CPU spends the
    great majority of its time at TPR 15, but it is not deaf. Pending
    interrupts latch in the LAPIC and are taken at the next instruction
    boundary whenever a passive window opens, and every cycle opens two:
    the teardown's record phase (native IDT, CR8 passive, hundreds of
    instructions) and the entry sliver before the gadget raises TPR
    again. Clock, IPIs and DPCs drain with microsecond-scale latency,
    and scheduler preemption inside the entry window is harmless
    (context switch preserves RCX/RIP; affinity keeps the CPU). The
    CPU is hogged, not hung: plan test runs accordingly.

Arguments:

    Target - The resolved KiRestoreProcessorControlState address. The
        contents are copied; the caller retains ownership.

Return Value:

    STATUS_SUCCESS with the thread cycling, or a failure status. On
    preparation failure nothing runs. On proof timeout the stop is set
    and the thread is given a bounded wait; if it still lives past that
    (near-impossible by construction) its tables are deliberately leaked
    rather than freed from underneath it.

--*/
{
    GROUP_AFFINITY Affinity;
    GROUP_AFFINITY PreviousAffinity;
    LARGE_INTEGER PollInterval;
    NTSTATUS Status;
    ULONG WaitedMs;

    PAGED_CODE();

    if (g_WorkerRunning)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    RtlZeroMemory(&Affinity, sizeof(Affinity));
    RtlZeroMemory(&PreviousAffinity, sizeof(PreviousAffinity));
    RtlZeroMemory(&g_WorkerProcessor, sizeof(g_WorkerProcessor));

    RtlCopyMemory(&g_WorkerTarget, Target, sizeof(g_WorkerTarget));

    (VOID)InterlockedExchange(&g_WorkerStopFlag, 0);

    //
    // Target: processor index 0, group 0 required. The legacy affinity
    // mask the new thread is pinned with cannot name another group.
    //

    Status = KeGetProcessorNumberFromIndex(0, &g_WorkerProcessor);

    if (!NT_SUCCESS(Status))
    {
        KmError("No processor index 0 - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        return Status;
    }

    if (g_WorkerProcessor.Group != 0)
    {
        KmError("First processor is in group %u, group 0 is required\n",
            (ULONG)g_WorkerProcessor.Group);
        return STATUS_NOT_SUPPORTED;
    }

    g_WorkerAffinityMask = (KAFFINITY)(1ULL << g_WorkerProcessor.Number);

    Affinity.Group = 0;
    Affinity.Mask = g_WorkerAffinityMask;

    KeSetSystemGroupAffinityThread(&Affinity, &PreviousAffinity);

    KmPrint("Worker pinned for setup - Cpu=%u:%u Cr3=0x%I64X\n",
        (ULONG)g_WorkerProcessor.Group, (ULONG)g_WorkerProcessor.Number,
        (ULONG64)__readcr3());

    Status = ApicInitialize(&g_WorkerApic);

    if (!NT_SUCCESS(Status))
    {
        KmError("APIC detection failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        return Status;
    }

    Status = TablesInitialize(&g_WorkerTables, &g_WorkerProcessor);

    if (!NT_SUCCESS(Status))
    {
        KmError("Tables failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        ApicUninitialize(&g_WorkerApic);
        KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        return Status;
    }

    WorkerFillAsmState(&g_WorkerProcessor);
    WorkerRecordSetup(&g_WorkerProcessor);

    //
    // Born in the gadget: IP is the routine, RCX will be the block.
    // x64 thread startup calls StartRoutine(StartContext), so the
    // first argument register carries the block into the gadget.
    //

    Status = PsCreateSystemThread(
        &g_WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)(ULONG_PTR)g_WorkerTarget.RoutineAddress,
        (PVOID)g_WorkerTables.Block
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Thread creation failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        TablesUninitialize(&g_WorkerTables);
        ApicUninitialize(&g_WorkerApic);
        KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        return Status;
    }

    Status = ObReferenceObjectByHandle(
        g_WorkerThreadHandle,
        THREAD_ALL_ACCESS,
        *PsThreadType,
        KernelMode,
        (PVOID*)&g_WorkerThreadObject,
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Thread reference failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = NULL;
        TablesUninitialize(&g_WorkerTables);
        ApicUninitialize(&g_WorkerApic);
        KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        return Status;
    }

    //
    // Pin the newborn to the prepared CPU before it can run anywhere
    // else. The window between creation and this call is a handful of
    // instructions on the creator; the gadget's straight-line prefix
    // (CR writes of identical System values, same-content LGDT/LIDT)
    // is benign on any CPU, and every teardown restores from the
    // captured natives of the CPU it then stays on. The set is read
    // back and compared: an unpinned thread must fail load, loudly.
    //

    Status = ZwSetInformationThread(
        g_WorkerThreadHandle,
        ThreadAffinityMask,
        &g_WorkerAffinityMask,
        sizeof(g_WorkerAffinityMask)
    );

    if (NT_SUCCESS(Status))
    {
        KAFFINITY ReadBack;

        ReadBack = 0;

        Status = ZwQueryInformationThread(
            g_WorkerThreadHandle,
            ThreadAffinityMask,
            &ReadBack,
            sizeof(ReadBack),
            NULL
        );

        if (NT_SUCCESS(Status) && (ReadBack != g_WorkerAffinityMask))
        {
            KmError("Affinity read-back mismatch - Set=0x%I64X Got=0x%I64X\n",
                (ULONG64)g_WorkerAffinityMask, (ULONG64)ReadBack);
            Status = STATUS_UNSUCCESSFUL;
        }
    }

    if (!NT_SUCCESS(Status))
    {
        KmError("Thread pinning failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        (VOID)InterlockedExchange(&g_WorkerStopFlag, 1);
        ObDereferenceObject(g_WorkerThreadObject);
        g_WorkerThreadObject = NULL;
        ZwClose(g_WorkerThreadHandle);
        g_WorkerThreadHandle = NULL;
        TablesUninitialize(&g_WorkerTables);
        ApicUninitialize(&g_WorkerApic);
        KeRevertToUserGroupAffinityThread(&PreviousAffinity);
        return Status;
    }

    KeRevertToUserGroupAffinityThread(&PreviousAffinity);

    KmPrint("Worker born - Routine=0x%I64X Block=%p Cpu=%u:%u\n",
        g_WorkerTarget.RoutineAddress, g_WorkerTables.Block,
        (ULONG)g_WorkerProcessor.Group, (ULONG)g_WorkerProcessor.Number);

    //
    // Proof poll: the #GP stub's stash means the thread faulted as
    // designed and entered the window.
    //

    PollInterval.QuadPart = -((LONGLONG)WORKER_PROOF_POLL_MS * 10000LL);
    WaitedMs = 0;

    for (;;)
    {
        if (InterlockedCompareExchange64(
                (LONG64 volatile*)&g_AsmEntryRsp, 0, 0) != 0)
        {
            break;
        }

        if (WaitedMs >= WORKER_PROOF_TIMEOUT_MS)
        {
            KmError("First cycle proof timed out - EntryRsp is still zero\n");
            (VOID)InterlockedExchange(&g_WorkerStopFlag, 1);
            WorkerWaitForFirstCycle();
            return STATUS_IO_TIMEOUT;
        }

        KeDelayExecutionThread(KernelMode, FALSE, &PollInterval);
        WaitedMs += WORKER_PROOF_POLL_MS;
    }

    g_WorkerRunning = TRUE;

    KmPrint("Worker cycling - EntryRsp=0x%I64X\n",
        (ULONG64)InterlockedCompareExchange64(
            (LONG64 volatile*)&g_AsmEntryRsp, 0, 0));

    return STATUS_SUCCESS;
}

static
VOID
WorkerWaitForFirstCycle(
    VOID
)
/*++

Routine Description:

    Bounded post-timeout wait used only when the first-cycle proof
    failed. Gives a living thread a chance to observe the stop and
    terminate itself; if it outlives the wait its tables stay allocated
    on purpose (freeing the IDT from underneath a thread that may still
    vector through it would corrupt whatever runs there instead).

Arguments:

    None.

Return Value:

    None. The thread objects are always released; the tables only when
    the thread provably exited.

--*/
{
    LARGE_INTEGER Timeout;
    NTSTATUS Status;

    PAGED_CODE();

    Timeout.QuadPart = -((LONGLONG)10000 * 10000LL);

    Status = KeWaitForSingleObject(
        g_WorkerThreadObject,
        Executive,
        KernelMode,
        FALSE,
        &Timeout
    );

    if (Status == STATUS_TIMEOUT)
    {
        KmError("Thread outlived the stop wait - leaking tables on purpose\n");
    }
    else
    {
        TablesUninitialize(&g_WorkerTables);
        ApicUninitialize(&g_WorkerApic);
    }

    ObDereferenceObject(g_WorkerThreadObject);
    g_WorkerThreadObject = NULL;

    ZwClose(g_WorkerThreadHandle);
    g_WorkerThreadHandle = NULL;
}

_Use_decl_annotations_
VOID
WorkerStop(
    VOID
)
/*++

Routine Description:

    Stops the experiment and releases everything. The flag is observed
    on the current cycle: inside the APIC_WRITE batch granularity, or
    at the next NMI teardown. The thread restores the natives and
    terminates itself, so the wait below is one cycle long at most.
    Only after it exited are the event history dumped and the tables,
    APIC window and thread objects released: every one of them is still
    reachable from the custom IDT paths until that point.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    if (!g_WorkerRunning)
    {
        return;
    }

    g_WorkerRunning = FALSE;

    KmPrint("Worker stopping\n");

    (VOID)InterlockedExchange(&g_WorkerStopFlag, 1);

    //
    // Unbounded wait: the thread is guaranteed to observe the flag on
    // its current cycle, tear the natives down and terminate itself.
    // Returning early would free the IDT from underneath it.
    //

    KeWaitForSingleObject(
        g_WorkerThreadObject,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    KmEventDump(&g_WorkerEvents);

    TablesUninitialize(&g_WorkerTables);
    ApicUninitialize(&g_WorkerApic);

    g_AsmEventBuffer = 0;
    g_AsmStopFlag = NULL;
    g_AsmBlock = 0;
    g_AsmRoutine = 0;

    ObDereferenceObject(g_WorkerThreadObject);
    g_WorkerThreadObject = NULL;

    ZwClose(g_WorkerThreadHandle);
    g_WorkerThreadHandle = NULL;

    KmPrint("Worker stopped - Cycles=%I64u\n",
        (ULONG64)InterlockedCompareExchange64(
            (LONG64 volatile*)&g_AsmCycleCount, 0, 0));
}

#pragma code_seg(pop)

#else

//
// Non x64 stub. The cycle protocol is x64 assembly.
//

_Use_decl_annotations_
NTSTATUS
WorkerStart(
    const RESTORE_TARGET* Target
)
{
    UNREFERENCED_PARAMETER(Target);

    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
VOID
WorkerStop(
    VOID
)
{
}

#endif
