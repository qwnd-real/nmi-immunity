#pragma once

#include <ntifs.h>

/*++

Module Name:

    Physical.h

Abstract:

    This module declares a single-PTE physical memory window for the
    experiment.

    One contiguous page is allocated at setup. The PTE base is
    discovered at setup by locating the self-referencing PML4 entry,
    because since Windows 10 1607 the self-reference index is
    randomized once per boot and no constant base can be assumed. The
    window's PTE is computed from the discovered base, its physical
    address is captured with MmGetPhysicalAddress, and the PTE itself
    is forced present and writable. The window virtual address, the
    PTE base, the PTE virtual address, the original PTE contents and
    the PTE physical address are kept together as the lifetime state.

    Only PhysicalInitialize is pageable and PASSIVE_LEVEL. Everything
    else is resident and runs at any IRQL up to and including
    HIGH_LEVEL: the hot paths touch only the stored PTE, one __invlpg
    and RtlCopyMemory, and never call the debugger, allocate, or take
    a lock. No lock is attempted anywhere: no lock primitive is legal
    at HIGH_LEVEL.

    There is exactly one global window. Callers serialize all
    PhysicalSetBacking/PhysicalRead/PhysicalWrite calls against each
    other and against teardown. The read/write buffers must be resident
    for the duration of the call; nothing here probes or faults them
    in, because neither is possible at HIGH_LEVEL.

    Caching is inherited from the contiguous allocation (write-back).
    That is correct for RAM. Uncached device memory wants different
    PCD/PWT handling and is out of scope for this window.

--*/

/*++

Structure Description:

    Lifetime state for the window. Window is the page-aligned virtual
    address that translates through Pte. PteBase is the discovered PTE
    array base for this boot. Pte is the virtual address of that
    translation's PTE under the discovered base. OriginalPte is the PTE
    contents to restore at teardown. PtePhysicalAddress is the byte
    physical address of the PTE itself, captured once at setup for
    diagnostics. Every field is zero until PhysicalInitialize succeeds.

--*/

typedef struct _PHYSICAL_STATE
{
    PVOID Window;
    ULONG64 PteBase;
    volatile ULONG64* Pte;
    ULONG64 OriginalPte;
    ULONG64 PtePhysicalAddress;
} PHYSICAL_STATE, *PPHYSICAL_STATE;

//
// Setup and teardown. Initialize allocates the window, captures the
// PTE state and forces the PTE present and writable. Uninitialize
// restores the original PTE, flushes the window and frees the page.
// Teardown must run at PASSIVE_LEVEL with no window user in flight:
// the restore is the last use of the PTE, which the caller guarantees
// by serializing against the hot paths.
//

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PhysicalInitialize(
    VOID
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
PhysicalUninitialize(
    VOID
);

//
// Points the window at a new backing page and flushes the stale
// translation with a single INVLPG. The address may be byte granular;
// the page frame it falls in becomes the window's page frame. Flag
// bits come from the captured original, with present, writable,
// accessed and dirty forced on.
//

_IRQL_requires_max_(HIGH_LEVEL)
VOID
PhysicalSetBacking(
    _In_ ULONG64 PhysicalAddress
);

//
// Byte-granular physical copy through the window, one page per backing
// switch. The caller supplies a resident buffer and serializes against
// every other window user. Returns STATUS_INVALID_DEVICE_STATE when
// the window is not initialized.
//

_Must_inspect_result_
_IRQL_requires_max_(HIGH_LEVEL)
NTSTATUS
PhysicalRead(
    _In_ ULONG64 PhysicalAddress,
    _Out_writes_bytes_(Size) PVOID Buffer,
    _In_ SIZE_T Size
);

_Must_inspect_result_
_IRQL_requires_max_(HIGH_LEVEL)
NTSTATUS
PhysicalWrite(
    _In_ ULONG64 PhysicalAddress,
    _In_reads_bytes_(Size) PCVOID Buffer,
    _In_ SIZE_T Size
);

//
// Resident accessors for diagnostics. They report NULL and zero while
// the window is not initialized.
//

_IRQL_requires_max_(HIGH_LEVEL)
PVOID
PhysicalGetWindow(
    VOID
);

_IRQL_requires_max_(HIGH_LEVEL)
ULONG64
PhysicalGetPtePhysicalAddress(
    VOID
);

_IRQL_requires_max_(HIGH_LEVEL)
BOOLEAN
PhysicalIsReady(
    VOID
);
