#include "Apic.h"
#include "Debug.h"

#include <intrin.h>

/*++

Module Name:

    Apic.cpp

Abstract:

    This module implements the detection half of Apic.h. It decides once,
    at setup, whether the self-NMI request goes through the legacy memory
    mapped window or the x2APIC MSR, and for xAPIC it maps the register
    page. The request itself lives in Asm.asm.

    The deliberate design limit, documented for every reader: the ICR
    write completes, but the architecture latches "NMI pending" as a
    single bit, not a count. A foreign NMI raised in the window between
    the write and delivery coalesces with the self-NMI into one
    delivery. The handler's RIP test consumes such a delivery as an
    expected self-NMI; if no second request remained latched, the
    foreign event never reaches Windows. This is a bounded reinjection
    rate, not a guarantee, and no observation available inside the
    handler can change that.

--*/

#define APIC_POOL_TAG                   'pAmN'

#if defined(_AMD64_)

#pragma code_seg(push)
#pragma code_seg("PAGE")

_Use_decl_annotations_
NTSTATUS
ApicInitialize(
    PAPIC_STATE State
)
/*++

Routine Description:

    Detects the active APIC interface and maps the xAPIC window when
    needed. CPUID.1 ECX[21] reports x2APIC support; the IA32_APIC_BASE
    MSR reports whether the local APIC is enabled and whether x2APIC
    mode is actually on. Support without enablement still means xAPIC.

Arguments:

    State - Receives the detection result. Zeroed first; the xAPIC
        mapping is NULL in x2APIC mode.

Return Value:

    STATUS_SUCCESS or a failure status. A disabled local APIC fails
    setup: there is no interface to request through.

--*/
{
    int CpuInfo[4];
    ULONG64 ApicBase;
    PHYSICAL_ADDRESS Physical;
    PVOID Mapping;

    PAGED_CODE();

    RtlZeroMemory(State, sizeof(*State));
    State->Mode = APIC_MODE_XAPIC;

    //
    // CPUID.1: ECX bit 21 is x2APIC support. __cpuid is a compiler
    // intrinsic, valid at PASSIVE_LEVEL in any thread context.
    //

    __cpuid(CpuInfo, 1);

    ApicBase = __readmsr(APIC_MSR_BASE);

    if ((ApicBase & APIC_BASE_ENABLE_BIT) == 0)
    {
        KmError("Local APIC is disabled (BASE=0x%I64X)\n", ApicBase);
        return STATUS_DEVICE_NOT_CONNECTED;
    }

    if (((CpuInfo[2] & (1 << 21)) != 0) &&
        ((ApicBase & APIC_BASE_X2APIC_BIT) != 0))
    {
        State->Mode = APIC_MODE_X2APIC;

        KmPrint("APIC mode - x2APIC (BASE=0x%I64X)\n", ApicBase);
        return STATUS_SUCCESS;
    }

    //
    // xAPIC: map the 4K register page non-cached. Only the ICR pair is
    // ever touched, by the assembly window, but the whole page is the
    // mapping granularity.
    //

    Physical.QuadPart = (LONGLONG)(ApicBase & APIC_BASE_ADDRESS_MASK);

    Mapping = MmMapIoSpace(Physical, PAGE_SIZE, MmNonCached);

    if (Mapping == NULL)
    {
        KmError("Failed to map the xAPIC page at 0x%I64X\n",
            (ULONG64)Physical.QuadPart);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    State->XapicMapping = Mapping;
    State->IcrLow = (volatile ULONG*)((PUCHAR)Mapping +
                                      APIC_XAPIC_ICR_LOW_OFFSET);
    State->IcrHigh = (volatile ULONG*)((PUCHAR)Mapping +
                                       APIC_XAPIC_ICR_HIGH_OFFSET);

    KmPrint("APIC mode - xAPIC (Base=0x%I64X Mapping=%p)\n",
        (ULONG64)Physical.QuadPart, Mapping);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
ApicUninitialize(
    PAPIC_STATE State
)
/*++

Routine Description:

    Unmaps the xAPIC window when one was mapped. Safe to call after a
    failed ApicInitialize. Must run at PASSIVE_LEVEL with no experiment
    in flight: the assembly window dereferences the mapping.

Arguments:

    State - The detection result.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    if (State->XapicMapping != NULL)
    {
        MmUnmapIoSpace(State->XapicMapping, PAGE_SIZE);
        State->XapicMapping = NULL;
        State->IcrLow = NULL;
        State->IcrHigh = NULL;

        KmTrace("xAPIC window unmapped\n");
    }
}

_Use_decl_annotations_
VOID
ApicPublishMarkers(
    PAPIC_STATE State
)
/*++

Routine Description:

    No-op in the final design. The ICR write and its markers live in the
    same assembly file as the NMI handler, so the handler compares the
    interrupted RIP against its own labels directly. There is nothing to
    copy: the mode in State is mirrored into the assembly-owned
    g_AsmApicMode by the worker before the first cycle.

Arguments:

    State - Unused.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    UNREFERENCED_PARAMETER(State);
}

#pragma code_seg(pop)

#else

//
// Non x64 stub. The experiment needs CR8, LGDT/LIDT and the xAPIC/x2APIC
// MSRs, so it is x64 only.
//

_Use_decl_annotations_
NTSTATUS
ApicInitialize(
    PAPIC_STATE State
)
{
    RtlZeroMemory(State, sizeof(*State));
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
VOID
ApicUninitialize(
    PAPIC_STATE State
)
{
    UNREFERENCED_PARAMETER(State);
}

_Use_decl_annotations_
VOID
ApicPublishMarkers(
    PAPIC_STATE State
)
{
    UNREFERENCED_PARAMETER(State);
}

#endif
