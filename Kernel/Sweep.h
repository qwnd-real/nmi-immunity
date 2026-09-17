#pragma once

#include <ntifs.h>

/*++

Module Name:

    Sweep.h

Abstract:

    This module declares the stale gadget-thread sweep that runs once
    in DriverEntry, after the restore target is resolved and before
    anything new is born inside it.

    A previous instance that died without unloading would otherwise
    keep executing freed descriptor state the moment NMIs resume. The
    sweep walks the System process through ZwGetNextThread -- threads
    born inside the gadget can only exist there, so nothing else is
    scanned -- and terminates whatever was born inside it. Worker
    threads are born with the gadget as their start address, and
    nothing else ever is, so the start address alone is exact: no
    legitimate passerby (a CPU coming online runs KiRestore, but is
    born elsewhere) can match it.

    Termination rides a kernel-mode APC queued to the target: no
    terminate routine is exported to drivers, so the sweep allocates
    one APC whose normal routine terminates its own thread. Delivery
    needs the target below dispatch level with APCs enabled, which a
    cycling worker reaches within a cycle or two.

    Deliberately absent is any interrupted-RIP test. Reading another
    thread's RIP waits without timeout for the target to reach a safe
    point, and one wedged target wedges the whole load with no pass
    bound able to save it -- that failure mode was observed, not
    theorized. Every observation the sweep makes is non-blocking by
    construction, so passes repeat until a full walk observes nothing,
    bounded by SWEEP_MAX_PASSES. Leftovers fail the load.

--*/

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
SweepGadgetThreads(
    _In_ ULONG64 GadgetBase
);
