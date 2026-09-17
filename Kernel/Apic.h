#pragma once

#include <ntifs.h>

/*++

Module Name:

    Apic.h

Abstract:

    This module declares the local APIC delivery mechanism for nmi-immunity: 
    one self-NMI request per cycle, issued either through the
    legacy memory mapped interface (xAPIC) or the MSR interface (x2APIC),
    chosen once at setup from CPUID.1 ECX[21] plus the IA32_APIC_BASE
    ENABLE and X2APIC bits.

    The actual ICR write lives in assembly (Asm.asm), because nmi-immunity
    needs an architectural boundary exactly after the write:
    the marker that follows it is the one observable the NMI handler's
    RIP test uses. The C++ side owns detection, state and teardown.

    The deliberate design limit, documented for every reader: the ICR
    write completes, but the architecture latches "NMI pending" as a
    single bit, not a count -- and there are two such single-bit stages
    in series (the LAPIC pending latch plus the CPU pending-while-blocked
    latch). A foreign NMI raised in the window between the write and
    delivery coalesces with the self-NMI into one delivery. The
    handler's RIP test consumes such a delivery as an expected self-NMI;
    if no second request remained latched, the foreign event never
    reaches Windows. This is a bounded reinjection rate, not a
    guarantee, and no observation available inside the handler can change
    that. ICR-committed is not latch-armed: a freshly issued request
    spends a short acceptance gap (delivery-status busy, latch still
    empty) in flight, during which the cycle can advance past the issue
    point; post-stash pre-Committed arrivals are therefore treated as an
    expected drop (teardown, no synthetic) rather than foreign, preferring
    a bounded FN over any FP.

    Foreign here means a delivery with RIP below the active mode's
    Committed marker: no request of ours can be outstanding there, so it
    is someone else's -- on the target, an ICR-sent NMI from Windows or
    an anti-cheat, sourceless by construction exactly like our own. The
    stub answers with exactly one synthetic self-NMI, the design's only
    allowed crosser: consumed natively right after the teardown's
    restore+iretq, where the sender's expecting NMI callback claims it,
    timing intact to microseconds and indistinguishable from the
    original to any check the protocol could run (an NMI carries no
    token to bind). If nothing claims it, Windows answers the sourceless
    delivery with NMI_HARDWARE_FAILURE; that outcome proves an unclaimed
    foreign arrived and is the accepted cost of the reinjection
    requirement. Everything else enforces the other half: loop issues
    never cross (issues only at the loop top, every delivery consumed in
    a stub, stop paths draining rather than terminating over a pending
    request), so any sourceless NMI the native handler ever sees is
    exactly one deliberate answer to a consumed foreign.

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
// IA32_APIC_BASE MSR layout and the x2APIC ID/ICR MSRs. The mode decision
// reads CPUID.1 ECX[21] (x2APIC support) and the ENABLE_X2APIC bit;
// topology leaves such as CPUID.0x1A describe cores, not the interface.
//

#define APIC_MSR_BASE                   0x1BUL
#define APIC_MSR_X2APIC_ID              0x802UL
#define APIC_MSR_X2APIC_ICR             0x830UL
#define APIC_BASE_ENABLE_BIT            0x800UL
#define APIC_BASE_X2APIC_BIT            0x400UL
#define APIC_BASE_ADDRESS_MASK          0xFFFFFF000ULL

//
// xAPIC register offsets from the mapped base.
//

#define APIC_XAPIC_ID_OFFSET            0x020UL
#define APIC_XAPIC_ICR_LOW_OFFSET       0x300UL
#define APIC_XAPIC_ICR_HIGH_OFFSET      0x310UL

//
// Pause iterations between reissues inside the assembly window. This is
// a watchdog resend interval in instructions, not a timeout and not a
// duty-cycle knob: steady-state delivery aborts the spin after the
// delivery latency D (tens of pause iterations), so any ceiling far
// above D never executes. Keep the ceiling at ~10-50x p99.9 D, well
// below tolerable unload latency.
//

#define APIC_PAUSE_ITERATIONS           20000UL

//
// Disarmed dwell iterations (pause instructions) executed once per cycle
// in the #GP stub after the stash and before the first ICR write, with
// the custom IDT loaded and the NMI latch provably empty. This extends
// the cycle period T without extending the armed window L, moving along
// the P = 1 - L/T frontier. Point A is the balanced default (98-99%,
// ~5k NMI/s); point B is the deep metric-run option (99.8-99.9%,
// ~500/s). All quoted rates are modern silicon (~140 cycles/pause)
// at ~3 GHz and scale linearly with TSC frequency; on older silicon
// (~13 cycles/pause) the same counts give ~10x shorter holds --
// calibrate W on the target from the metric TSC deltas rather than
// trusting the defaults blindly. Exposed through g_AsmDwellIters so the
// operating point is tunable without rebuilding the dispatch.
//

#define APIC_DWELL_PAUSES_BALANCED      4100UL
#define APIC_DWELL_PAUSES_DEEP          42000UL
#define APIC_DWELL_PAUSES_DEFAULT       APIC_DWELL_PAUSES_BALANCED

/*++

Structure Description:

    Detection result, the target's physical APIC ID and, for xAPIC, the
    mapped register window. Capture while pinned to the target processor;
    a Windows processor number is not an APIC ID. Asm.asm uses explicit
    physical destination addressing for both loop and synthetic NMIs.
    The ICR writes stay in assembly so the markers immediately follow them.

--*/

typedef struct _APIC_STATE
{
    ULONG Mode;
    ULONG ApicId;
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
