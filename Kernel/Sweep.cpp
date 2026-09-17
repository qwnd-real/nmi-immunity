#include "Sweep.h"
#include "Debug.h"

/*++

Module Name:

    Sweep.cpp

Abstract:

    This module implements the sweep declared in Sweep.h.

    The System process is enumerated through ZwGetNextThread, which
    needs no structure parsing and no version dependent offsets. Every
    handle is a kernel handle, opened for exactly query rights, and
    closed on the same walk. Every observation primitive is
    non-blocking by construction: two information queries, one object
    reference, one APC queue. The sweep never captures a thread's
    context and never suspends one, so no target, however wedged, can
    stall a pass.

--*/

//
// The sweep is architecture neutral: start addresses, object
// references and APCs work identically on x64 and ARM64, and no
// context capture remains. It runs on every configuration the driver
// builds for.
//

//
// Pass bound and pacing. Termination lands as an APC below dispatch
// level, which a cycling worker reaches within a cycle or two, so
// fifty 100 ms passes is generous. A quiesced box exits after one
// pass: a walk that matches nothing is silence, proven in a single
// observation.
//

#define SWEEP_MAX_PASSES                50
#define SWEEP_PASS_DELAY_MS             100

//
// Walk cap on an undocumented enumerator: the walk provably ends at
// the list tail, but a pathological box costs passes, never eternity.
// See the loop body.
//

#define SWEEP_MAX_THREADS_PER_PASS      65536

#define SWEEP_POOL_TAG                  'pWsN'

//
// None of the thread-enumeration surface used below is declared in
// the driver headers this target builds against, so every prototype,
// access right and info class is mirrored here exactly the way
// KmModule mirrors ZwQuerySystemInformation. Values are stable kernel
// ABI. The #ifndef guards keep this correct even where a header does
// declare them: identical redefinition is benign.
//
// Two deliberate substitutions, both verified against ntoskrnl.lib:
// ZwGetContextThread is not exported (and reading another thread's
// context waits without timeout, so it is unusable here regardless);
// ZwTerminateThread is not exported either, so the kill queues a
// kernel-mode termination APC (KeInitializeApc plus KeInsertQueueApc,
// both exported) whose normal routine terminates its own thread.
// KAPC itself still comes from the headers; only the trimmed
// environment enum, routine types and prototypes are mirrored here.
//

typedef enum _SWEEP_THREADINFOCLASS
{
    SweepThreadBasicInformation = 0,
    SweepThreadQuerySetWin32StartAddress = 9
} SWEEP_THREADINFOCLASS;

typedef enum _SWEEP_APC_ENVIRONMENT
{
    SweepOriginalApcEnvironment = 0,
    SweepAttachedApcEnvironment = 1,
    SweepCurrentApcEnvironment = 2,
    SweepInsertApcEnvironment = 3
} SWEEP_APC_ENVIRONMENT;

typedef
VOID
(*PSWEEP_NORMAL_ROUTINE)(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

typedef
VOID
(*PSWEEP_RUNDOWN_ROUTINE)(
    _In_ PKAPC Apc
);

typedef
VOID
(*PSWEEP_KERNEL_ROUTINE)(
    _In_ PKAPC Apc,
    _Inout_ PSWEEP_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

EXTERN_C_START

NTKERNELAPI
NTSTATUS
ZwGetNextThread(
    _In_ HANDLE ProcessHandle,
    _In_opt_ HANDLE ThreadHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ ULONG HandleAttributes,
    _In_ ULONG Flags,
    _Out_ PHANDLE NewThreadHandle
);

NTKERNELAPI
NTSTATUS
ZwQueryInformationThread(
    _In_ HANDLE ThreadHandle,
    _In_ SWEEP_THREADINFOCLASS ThreadInformationClass,
    _Out_writes_bytes_(ThreadInformationLength) PVOID ThreadInformation,
    _In_ ULONG ThreadInformationLength,
    _Out_opt_ PULONG ReturnLength
);

NTKERNELAPI
VOID
KeInitializeApc(
    _Out_ PKAPC Apc,
    _In_ PKTHREAD Thread,
    _In_ SWEEP_APC_ENVIRONMENT Environment,
    _In_ PSWEEP_KERNEL_ROUTINE KernelRoutine,
    _In_opt_ PSWEEP_RUNDOWN_ROUTINE RundownRoutine,
    _In_ PSWEEP_NORMAL_ROUTINE NormalRoutine,
    _In_ KPROCESSOR_MODE ApcMode,
    _In_opt_ PVOID NormalContext
);

NTKERNELAPI
BOOLEAN
KeInsertQueueApc(
    _Inout_ PKAPC Apc,
    _In_opt_ PVOID SystemArgument1,
    _In_opt_ PVOID SystemArgument2,
    _In_ KPRIORITY Increment
);

EXTERN_C_END

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION   0x1000UL
#endif

#ifndef THREAD_TERMINATE
#define THREAD_TERMINATE                    0x0001UL
#endif

#ifndef THREAD_GET_CONTEXT
#define THREAD_GET_CONTEXT                  0x0008UL
#endif

#ifndef THREAD_QUERY_LIMITED_INFORMATION
#define THREAD_QUERY_LIMITED_INFORMATION    0x0800UL
#endif

/*++

Structure Description:

    THREAD_BASIC_INFORMATION as returned by ThreadBasicInformation:
    exit status, TEB base, client ID, affinity mask and priorities.
    Mirrored locally so the sweep needs no version dependent header
    for it; only ClientId.UniqueThread is ever read.

--*/

typedef struct _SWEEP_THREAD_BASIC
{
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    LONG BasePriority;
} SWEEP_THREAD_BASIC, *PSWEEP_THREAD_BASIC;

C_ASSERT(sizeof(SWEEP_THREAD_BASIC) == 48);

//
// Forward declarations for internal helper functions.
//

static
PETHREAD
SweepInspectThread(
    _In_ HANDLE ThreadHandle,
    _In_ ULONG64 GadgetBase,
    _Out_ PULONG64 ThreadId
);

static
NTSTATUS
SweepTerminateThread(
    _In_ PETHREAD Target
);

static
VOID
SweepApcNormalRoutine(
    _In_ PVOID NormalContext,
    _In_ PVOID SystemArgument1,
    _In_ PVOID SystemArgument2
);

static
VOID
SweepApcKernelRoutine(
    _In_ PKAPC Apc,
    _Inout_ PSWEEP_NORMAL_ROUTINE* NormalRoutine,
    _Inout_ PVOID* NormalContext,
    _Inout_ PVOID* SystemArgument1,
    _Inout_ PVOID* SystemArgument2
);

static
VOID
SweepApcRundownRoutine(
    _In_ PKAPC Apc
);

#pragma code_seg(push)
#pragma code_seg("PAGE")

static
PETHREAD
SweepInspectThread(
    HANDLE ThreadHandle,
    ULONG64 GadgetBase,
    PULONG64 ThreadId
)
/*++

Routine Description:

    Tests one thread by start address and, on a match, hands back a
    referenced object for the kill. Client ID, start address and object
    reference are all non-blocking queries: nothing here waits on
    another CPU, which is the entire point. Reading a thread's
    interrupted RIP (PsGetContextThread) waits without timeout for the
    target to reach a safe point, and one wedged target wedges the
    whole load; the RIP window was removed for exactly that reason. A
    thread born inside the gadget is identified exactly by its start
    address, and nothing else is ever born there.

Arguments:

    ThreadHandle - Kernel handle with query rights. The object
        reference is taken inside.

    GadgetBase - The start address every thread of ours is born with.

    ThreadId - Receives the thread ID on a match, for the log line.

Return Value:

    A referenced ETHREAD on a start-address match. The caller owns one
    reference and must dereference it. NULL otherwise.

--*/
{
    SWEEP_THREAD_BASIC Basic;
    ULONG64 StartAddress;
    ULONG Returned;
    PETHREAD Object;
    NTSTATUS Status;

    PAGED_CODE();

    *ThreadId = 0;

    RtlZeroMemory(&Basic, sizeof(Basic));

    Status = ZwQueryInformationThread(
        ThreadHandle,
        SweepThreadBasicInformation,
        &Basic,
        sizeof(Basic),
        &Returned
    );

    if ((!NT_SUCCESS(Status)) || (Returned < sizeof(Basic)))
    {
        return NULL;
    }

    *ThreadId = (ULONG64)(ULONG_PTR)Basic.ClientId.UniqueThread;

    StartAddress = 0;
    Returned = 0;

    Status = ZwQueryInformationThread(
        ThreadHandle,
        SweepThreadQuerySetWin32StartAddress,
        &StartAddress,
        sizeof(StartAddress),
        &Returned
    );

    if (!NT_SUCCESS(Status) || (StartAddress != GadgetBase))
    {
        return NULL;
    }

    //
    // Match: reference for the kill, skipping the loading thread
    // itself by identity. DriverEntry is never born in the gadget,
    // so a self-match would mean terminating the load.
    //

    Object = NULL;

    Status = ObReferenceObjectByHandle(
        ThreadHandle,
        0,
        *PsThreadType,
        KernelMode,
        (PVOID*)&Object,
        NULL
    );

    if (!NT_SUCCESS(Status))
    {
        return NULL;
    }

    if (Object == PsGetCurrentThread())
    {
        ObDereferenceObject(Object);
        return NULL;
    }

    return Object;
}

static
NTSTATUS
SweepTerminateThread(
    PETHREAD Target
)
/*++

Routine Description:

    Queues a kernel-mode termination APC to the target. The normal
    routine runs on the target thread itself once it drops below
    dispatch level with APCs enabled -- a cycling worker reaches that
    point within a cycle or two -- and terminates the calling thread,
    which is the only thread PsTerminateSystemThread can terminate.
    Exactly one of the kernel and rundown routines frees the
    allocation: delivery frees it on pickup, thread exit frees it on
    rundown. A refused insert means the thread is already exiting, and
    the rescan loop observes the absence.

Arguments:

    Target - Referenced thread object. The caller keeps its own
        reference: a queued APC holds one of its own.

Return Value:

    STATUS_SUCCESS with the APC queued, STATUS_INSUFFICIENT_RESOURCES
    without an allocation, or STATUS_THREAD_IS_TERMINATING when the
    thread refused the queue.

--*/
{
    PKAPC Apc;

    PAGED_CODE();

    Apc = (PKAPC)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(KAPC),
        SWEEP_POOL_TAG
    );

    if (Apc == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeApc(
        Apc,
        (PKTHREAD)Target,
        SweepOriginalApcEnvironment,
        SweepApcKernelRoutine,
        SweepApcRundownRoutine,
        SweepApcNormalRoutine,
        KernelMode,
        NULL
    );

    if (!KeInsertQueueApc(Apc, NULL, NULL, 0))
    {
        ExFreePoolWithTag(Apc, SWEEP_POOL_TAG);
        return STATUS_THREAD_IS_TERMINATING;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
SweepGadgetThreads(
    ULONG64 GadgetBase
)
/*++

Routine Description:

    Terminates every thread born inside the gadget, then verifies
    silence. The start address alone is the discriminator: worker
    threads are born with the gadget as their start routine, and
    nothing else ever is. Passes repeat until a full walk observes
    nothing. Termination rides an APC and is asynchronous, so a kill
    is always followed by at least one confirming pass.

Arguments:

    GadgetBase - The resolved routine address. Zero is rejected: it
        would match nothing real while reporting success.

Return Value:

    STATUS_SUCCESS with no gadget-born thread observed on the final
    pass.

    STATUS_INVALID_PARAMETER for a null gadget base.

    STATUS_TIMEOUT when passes exhaust with threads still observed in
    the window.

--*/
{
    ULONG Pass;
    ULONG KilledTotal;
    LARGE_INTEGER Delay;

    PAGED_CODE();

    if (GadgetBase == 0)
    {
        return STATUS_INVALID_PARAMETER;
    }

    KilledTotal = 0;

    Delay.QuadPart = -(LONGLONG)SWEEP_PASS_DELAY_MS * 10000LL;

    for (Pass = 0; Pass < SWEEP_MAX_PASSES; Pass += 1)
    {
        ULONG Observed;
        ULONG Scanned;
        PEPROCESS SystemProcess;
        HANDLE ProcessHandle;
        NTSTATUS Status;

        Observed = 0;
        Scanned = 0;
        ProcessHandle = NULL;

        //
        // System only, by process ID 4: threads born inside the
        // gadget are system threads by construction, and no
        // user-mode thread can be interrupted inside kernel code it
        // can never execute. One process, no process enumeration, no
        // context captures at all.
        //

        Status = PsLookupProcessByProcessId((HANDLE)4, &SystemProcess);

        if (NT_SUCCESS(Status))
        {
            Status = ObOpenObjectByPointer(
                SystemProcess,
                OBJ_KERNEL_HANDLE,
                NULL,
                PROCESS_QUERY_LIMITED_INFORMATION,
                *PsProcessType,
                KernelMode,
                &ProcessHandle);

            ObDereferenceObject(SystemProcess);
        }

        if (NT_SUCCESS(Status))
        {
            HANDLE ThreadHandle;
            HANDLE NextThreadHandle;

            ThreadHandle = NULL;

            while (TRUE)
            {
                ULONG64 ThreadId;
                PETHREAD Target;

                NextThreadHandle = NULL;

                Status = ZwGetNextThread(
                    ProcessHandle,
                    ThreadHandle,
                    THREAD_QUERY_LIMITED_INFORMATION,
                    OBJ_KERNEL_HANDLE,
                    0,
                    &NextThreadHandle
                );

                if (ThreadHandle != NULL)
                {
                    ZwClose(ThreadHandle);
                    ThreadHandle = NULL;
                }

                if (!NT_SUCCESS(Status))
                {
                    break;
                }

                //
                // Paranoia cap on an undocumented enumerator: the walk
                // provably ends at the list tail, but a pathological
                // box must cost passes, never eternity. An unfinished
                // pass counts as observed so quiescence requires a
                // completed walk.
                //

                Scanned += 1;

                if (Scanned > SWEEP_MAX_THREADS_PER_PASS)
                {
                    KmWarning("Sweep pass truncated - Pass=%u\n",
                        Pass + 1);
                    Observed += 1;
                    ZwClose(NextThreadHandle);
                    break;
                }

                ThreadHandle = NextThreadHandle;

                //
                // A non-NULL return is a referenced object the caller
                // owns: kill through it or dereference it.
                //

                Target = SweepInspectThread(
                    ThreadHandle,
                    GadgetBase,
                    &ThreadId);

                if (Target == NULL)
                {
                    continue;
                }

                Observed += 1;

                Status = SweepTerminateThread(Target);

                ObDereferenceObject(Target);

                if (NT_SUCCESS(Status))
                {
                    KilledTotal += 1;
                    KmWarning("Terminating gadget-born thread - "
                        "Tid=%I64u Gadget=0x%I64X\n",
                        ThreadId, GadgetBase);
                }
                else
                {
                    KmWarning("Failed to terminate gadget thread - "
                        "Tid=%I64u Status=%s (0x%08X)\n",
                        ThreadId, KmStatusToString(Status), Status);
                }
            }

            ZwClose(ProcessHandle);
            ProcessHandle = NULL;
        }
        else
        {
            KmWarning("Sweep pass skipped - System unresolvable (%s)\n",
                KmStatusToString(Status));
        }

        if (Observed == 0)
        {
            KmPrint("Gadget sweep quiesced - Passes=%u Killed=%u\n",
                Pass + 1, KilledTotal);
            return STATUS_SUCCESS;
        }

        //
        // TRACE-level progress: silent by default, visible with the
        // trace mask when a sweep grinds, so a slow pass is
        // attributable to enumeration rather than to later stages.
        //

        KmTrace("Gadget sweep pass - Pass=%u Observed=%u Killed=%u\n",
            Pass + 1, Observed, KilledTotal);

        (VOID)KeDelayExecutionThread(KernelMode, FALSE, &Delay);
    }

    KmError("Gadget sweep timed out - Killed=%u\n", KilledTotal);
    return STATUS_TIMEOUT;
}

//
// RESIDENT APC ROUTINES. The normal routine runs on the target thread
// itself at PASSIVE_LEVEL, where terminating the calling thread is
// legal. The kernel routine frees the allocation on delivery and the
// rundown routine frees it if the thread exits first, so exactly one
// of the two runs. No PAGED_CODE here: the kernel routine executes at
// APC_LEVEL.
//

static
VOID
SweepApcNormalRoutine(
    PVOID NormalContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    //
    // Never returns on success: the target thread dies here.
    //

    (VOID)PsTerminateSystemThread(STATUS_CONTROL_C_EXIT);
}

static
VOID
SweepApcKernelRoutine(
    PKAPC Apc,
    PSWEEP_NORMAL_ROUTINE* NormalRoutine,
    PVOID* NormalContext,
    PVOID* SystemArgument1,
    PVOID* SystemArgument2
)
{
    UNREFERENCED_PARAMETER(NormalRoutine);
    UNREFERENCED_PARAMETER(NormalContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    ExFreePoolWithTag(Apc, SWEEP_POOL_TAG);
}

static
VOID
SweepApcRundownRoutine(
    PKAPC Apc
)
{
    ExFreePoolWithTag(Apc, SWEEP_POOL_TAG);
}

#pragma code_seg(pop)
