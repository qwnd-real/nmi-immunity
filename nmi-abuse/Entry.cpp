#include "Entry.h"
#include "Restore.h"
#include "Worker.h"
#include "Debug.h"

/*++

Module Name:

    Entry.cpp

Abstract:

    This module implements the driver's load and unload entry points.

    The driver is a software only, non PnP kernel service with no device
    object and no interface. Everything happens in DriverEntry: the
    KiRestoreProcessorControlState signature is resolved in the loaded
    kernel image, and the pinned worker described in Worker.h is
    started. The custom IDT, the self-NMI window and the resume
    protocol are the only state that outlives DriverEntry, and the
    unload path stops them before anything else is released.

    Load is refused when discovery or startup fails: unlike the
    reference project, there is no diagnosable degraded mode here, only
    a running experiment or an unloaded driver.

--*/

#pragma code_seg(push)
#pragma code_seg("PAGE")

_Use_decl_annotations_
VOID
DriverUnload(
    PDRIVER_OBJECT DriverObject
)
/*++

Routine Description:

    Tears the driver down, in the reverse order of the setup.

    WorkerStop signals the stop first and returns only when the thread
    has torn the natives down and exited; only then is any other state
    touched. There is nothing else to release.

Arguments:

    DriverObject - The driver being unloaded.

Return Value:

    None.

--*/
{
    UNREFERENCED_PARAMETER(DriverObject);

    PAGED_CODE();

    KmPrint("Unloading\n");

    WorkerStop();

    KmPrint("Unloaded\n");
}

#pragma code_seg(pop)

#pragma code_seg(push)
#pragma code_seg("INIT")

_Use_decl_annotations_
NTSTATUS
DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

    Initializes the driver: resolves the restore routine in the native
    kernel image and starts the pinned worker that cycles through it.

    The VSL/HyperV branch inside the routine is assumed never taken on
    this machine; discovery cannot check that, it only finds the bytes.
    CPU pinning (inside the worker) is what keeps the captured CR3 and
    descriptor bases valid for every cycle.

Arguments:

    DriverObject - The driver object being initialized.

    RegistryPath - Path to this driver's service key. Valid only for
        the duration of this call.

Return Value:

    STATUS_SUCCESS with the experiment cycling, or a failure status
    with nothing running.

--*/
{
    RESTORE_TARGET Target;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    KmPrint("Loading - DriverObject=%p RegistryPath=%wZ\n",
        DriverObject, RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    RtlZeroMemory(&Target, sizeof(Target));

    Status = RestoreResolveTarget(&Target);

    if (!NT_SUCCESS(Status))
    {
        KmError("Restore target unavailable - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        return Status;
    }

    Status = WorkerStart(&Target);

    if (!NT_SUCCESS(Status))
    {
        KmError("Worker unavailable - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        return Status;
    }

    KmPrint("Loaded - Routine=0x%I64X\n", Target.RoutineAddress);

    return STATUS_SUCCESS;
}

#pragma code_seg(pop)
