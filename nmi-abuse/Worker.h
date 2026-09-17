#pragma once

#include <ntifs.h>
#include "Restore.h"

/*++

Module Name:

    Worker.h

Abstract:

    This module declares the pinned experiment thread. The worker pins
    the loading thread to the target CPU, captures that CPU's native
    descriptor state, points the assembly protocol at it and then
    creates one system thread born inside KiRestoreProcessorControlState
    with RCX set to the prepared block. That thread never leaves the
    gadget: every NMI teardown reenters it directly, and the stop paths
    terminate it on its clean stack.

    Pinning makes the captured CR3/GDTR/IDTR valid for every cycle
    without refresh. Creation and pinning of the new thread race by a
    handful of creator instructions; the gadget's straight-line prefix
    is benign on any CPU, and the thread is pinned before it can
    complete a cycle anywhere else.

--*/

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
WorkerStart(
    _In_ const RESTORE_TARGET* Target
);

//
// Signals the stop, waits for the thread's last cycle to tear down,
// dumps the event history and releases everything. Safe to call after
// a failed WorkerStart.
//

_IRQL_requires_(PASSIVE_LEVEL)
VOID
WorkerStop(
    VOID
);
