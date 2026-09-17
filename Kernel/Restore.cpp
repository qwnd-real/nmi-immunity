#include "Restore.h"
#include "KmModule.h"
#include "Debug.h"

/*++

Module Name:

    Restore.cpp

Abstract:

    This module implements the discovery declared in Restore.h.

    The native kernel image is located through the loaded module list and
    the supplied signature is scanned for inside its resident executable
    sections. Discovery succeeds only when the signature matches exactly
    once; a second match is a setup failure rather than a guessed target.

    The runtime branch around LGDT, LIDT and LTR is assumed never taken,
    as required by nmi-immunity. A byte match cannot inspect that
    condition: the flags live in data this module never reads.

--*/

//
// Exact signature supplied with the project:
//
//     mov rax, [rcx]
//     mov cr0, rax
//     mov rax, [rcx+10h]
//     mov cr3, rax
//
// Keep these bytes unmodified: they are the whole identification contract.
//

static const UCHAR RestoreSignature[] =
{
    0x48, 0x8B, 0x01, 0x0F, 0x22, 0xC0, 0x48,
    0x8B, 0x41, 0x10, 0x0F, 0x22, 0xD8
};

#pragma code_seg(push)
#pragma code_seg("PAGE")

_Use_decl_annotations_
NTSTATUS
RestoreResolveTarget(
    PRESTORE_TARGET Target
)
/*++

Routine Description:

    Locates the native kernel image and resolves the
    KiRestoreProcessorControlState signature inside it.

Arguments:

    Target - Receives the discovery result. The structure is zeroed
        first, so a failure never publishes partial data.

Return Value:

    STATUS_SUCCESS - Exactly one eligible match was found and reported.

    Any failure status from the module query or the pattern scan.

--*/
{
    NTSTATUS Status;
    ULONG64 Match;

    PAGED_CODE();

    RtlZeroMemory(Target, sizeof(*Target));

    Status = KmModuleQueryInfo(
        RESTORE_TARGET_MODULE,
        &Target->ImageBase,
        &Target->ImageSize
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Kernel image %ws not resolved - Status=%s (0x%08X)\n",
            RESTORE_TARGET_MODULE, KmStatusToString(Status), Status);
        return Status;
    }

    Status = KmModuleFindPattern(
        Target->ImageBase,
        Target->ImageSize,
        RestoreSignature,
        RTL_NUMBER_OF(RestoreSignature),
        &Match
    );

    if (!NT_SUCCESS(Status))
    {
        KmError("Signature not resolved in %ws - Status=%s (0x%08X)\n",
            RESTORE_TARGET_MODULE, KmStatusToString(Status), Status);
        return Status;
    }

    //
    // The match is an absolute virtual address. Record its image-relative
    // form too, so a debugger can map a crash RIP back to the scan result
    // without re-resolving the module list.
    //

    Target->SignatureLength = RTL_NUMBER_OF(RestoreSignature);
    Target->RoutineAddress = Match;
    Target->RoutineRva = Match - Target->ImageBase;

    KmPrint("Restore target ready - Base=0x%I64X Size=0x%X Routine=0x%I64X "
        "(RVA 0x%I64X)\n",
        Target->ImageBase, Target->ImageSize, Target->RoutineAddress,
        Target->RoutineRva);

    return STATUS_SUCCESS;
}

#pragma code_seg(pop)
