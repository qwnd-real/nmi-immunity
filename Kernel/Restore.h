#pragma once

#include <ntifs.h>

/*++

Module Name:

    Restore.h

Abstract:

    This module declares discovery of KiRestoreProcessorControlState in
    the loaded kernel image. Discovery requires one resident executable
    match for the supplied signature and reports both its absolute
    address and its image-relative offset.

    A discovered address is a candidate for the later processor-state
    protocol. This module never invokes it, changes descriptor state or
    sends an interrupt. Its result does not certify the return protocol,
    and it does not certify that the VSL/HyperV branch inside the routine
    is not taken: that branch is a runtime property of the machine, and
    the nmi-immunity assumes it is never taken.

--*/

//
// The module the signature lives in. One name, resolved through the
// loaded module list.
//

#define RESTORE_TARGET_MODULE           L"ntoskrnl.exe"

/*++

Structure Description:

    Immutable discovery result. The native kernel image remains loaded for
    the system lifetime, so no additional image reference is retained.
    Every field is zero on failure; partial discovery is never published.

--*/

typedef struct _RESTORE_TARGET
{
    ULONG64 ImageBase;
    ULONG ImageSize;
    ULONG SignatureLength;
    ULONG64 RoutineAddress;
    ULONG64 RoutineRva;
} RESTORE_TARGET, *PRESTORE_TARGET;

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
RestoreResolveTarget(
    _Out_ PRESTORE_TARGET Target
);
