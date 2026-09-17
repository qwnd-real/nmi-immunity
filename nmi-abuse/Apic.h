#pragma once

#include <ntifs.h>

/*++

Module Name:

    Apic.h

Abstract:

    This module declares the local APIC delivery mechanism for the
    experiment: one self-NMI request per cycle, issued either through the
    legacy memory mapped interface (xAPIC) or the MSR interface (x2APIC),
    chosen once at setup from CPUID.1 and CPUID.0x1A.

    The actual ICR write lives in assembly (Asm.asm), because the
    experiment needs an architectural boundary exactly after the write:
    the marker that follows it is the one observable the NMI handler's
    RIP test uses. The C++ side owns detection, state and teardown.

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

typedef struct _APIC_STATE APIC_STATE, *PAPIC_STATE;

//
// Selector for the assembly dispatch: the marker set to compare RIP
// against, and the write sequence to reissue after the pause window.
// The value is mirrored into the assembly-owned g_AsmApicMode.
//

#define APIC_MODE_XAPIC                 0UL
#define APIC_MODE_X2APIC                1UL

//
// IA32_APIC_BASE MSR layout and the x2APIC ICR MSR. The mode decision
// reads CPUID.1 ECX[21] (x2APIC support) and the ENABLE_X2APIC bit;
// topology leaves such as CPUID.0x1A describe cores, not the interface.
//

#define APIC_MSR_BASE                   0x1BUL
#define APIC_MSR_X2APIC_ICR             0x830UL
#define APIC_BASE_ENABLE_BIT            0x800UL
#define APIC_BASE_X2APIC_BIT            0x400UL
#define APIC_BASE_ADDRESS_MASK          0xFFFFFF000ULL

//
// xAPIC register offsets from the mapped base.
//

#define APIC_XAPIC_ICR_LOW_OFFSET       0x300UL
#define APIC_XAPIC_ICR_HIGH_OFFSET      0x310UL

//
// One self-NMI request: vector 0, NMI delivery mode (100b), self
// shorthand (01b). Level and trigger are ignored for NMI.
//

#define APIC_ICR_SELF_NMI_LOW           0x00040400UL
#define APIC_ICR_SELF_NMI_HIGH          0x00000000UL
#define APIC_ICR_SELF_NMI_X2APIC        0x0000000000040400ULL

//
// Pause iterations between reissues inside the assembly window. This is
// a resend interval in instructions, not a timeout.
//

#define APIC_PAUSE_ITERATIONS           100000UL

/*++

Structure Description:

    Detection result and, for xAPIC, the mapped register window. The ICR
    writes themselves live in Asm.asm so the marker can sit exactly after
    them; this structure only tells that code which interval is active
    and where the xAPIC registers are.

--*/

typedef struct _APIC_STATE
{
    ULONG Mode;
    PVOID XapicMapping;
    volatile ULONG* IcrLow;
    volatile ULONG* IcrHigh;
} APIC_STATE, *PAPIC_STATE;

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ApicInitialize(
    _Out_ PAPIC_STATE State
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ApicUninitialize(
    _Inout_ PAPIC_STATE State
);

//
// Publishes the marker addresses of the active APIC mode into the state
// the assembly dispatch reads. Called once per preparation cycle, before
// the custom descriptor state is loaded.
//

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ApicPublishMarkers(
    _Inout_ PAPIC_STATE State
);
