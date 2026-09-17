#include "Physical.h"
#include "Debug.h"

#include <intrin.h>

/*++

Module Name:

    Physical.cpp

Abstract:

    This module implements the single-PTE window declared in
    Physical.h.

    The window is one contiguous page, so its PTE is exclusive to the
    window: retargeting the PTE can never disturb a neighboring pool
    allocation sharing the same page. The PTE base is discovered at
    setup by scanning the live PML4 for the entry that references the
    PML4 itself, because the self-reference index has been randomized
    once per boot since Windows 10 1607 and no constant base holds.
    The window's PTE is computed from the discovered base, its physical
    address is captured once with MmGetPhysicalAddress, and the PTE is
    forced present and writable. Every later access writes a new page
    frame into that same PTE, executes INVLPG for the window, and
    copies through the window.

    Only PhysicalInitialize lives in PAGE and calls PAGED_CODE. The
    teardown and every hot path are resident: they run at any IRQL up
    to and including HIGH_LEVEL, where a page fault would be fatal
    rather than serviceable. The hot paths are silent by construction:
    text output is PASSIVE_LEVEL only, so a HIGH_LEVEL copy failure is
    a status, never a log line.

--*/

#if defined(_AMD64_)

//
// PTE bit contract. Only the frame changes per access; every flag is
// inherited from the captured original with the four bits below forced
// on. The NX bit (63) is preserved as captured, so the window is never
// made executable by the retarget.
//

#define PHYSICAL_PTE_PRESENT            0x0000000000000001ULL
#define PHYSICAL_PTE_WRITABLE           0x0000000000000002ULL
#define PHYSICAL_PTE_ACCESSED           0x0000000000000020ULL
#define PHYSICAL_PTE_DIRTY              0x0000000000000040ULL
#define PHYSICAL_PTE_LARGE              0x0000000000000080ULL
#define PHYSICAL_PTE_PFN_MASK           0x000FFFFFFFFFF000ULL
#define PHYSICAL_PTE_PAGE_OFFSET_MASK   0x0000000000000FFFULL

//
// PML4 discovery contract. The kernel keeps one self-referencing PML4
// entry whose frame is the PML4 itself. The entry's index is chosen
// once per boot from the kernel half, and the PTE array base for the
// boot is that index shifted to the PML4 position with the canonical
// sign extension. The CR4 LA57 bit selects 5-level paging, whose
// hierarchy this module does not implement.
//

#define PHYSICAL_PML4_ENTRY_COUNT       512
#define PHYSICAL_PML4_KERNEL_HALF_MIN   0x100
#define PHYSICAL_CR4_LA57               0x1000ULL
#define PHYSICAL_VA_SIGN_EXTENSION      0xFFFF000000000000ULL

//
// Lifetime state. Static non-paged storage: the hot paths dereference
// the PTE and the window at HIGH_LEVEL, where paged memory would be
// fatal rather than faultable. Ready flips only at setup and teardown,
// both serialized by the caller against every hot path.
//

static PHYSICAL_STATE g_PhysicalState;
static volatile BOOLEAN g_PhysicalReady = FALSE;

static
_IRQL_requires_max_(HIGH_LEVEL)
volatile ULONG64*
PhysicalPteForVa(
    _In_ ULONG64 PteBase,
    _In_ PVOID Va
)
/*++

Routine Description:

    Computes the PTE address for one virtual address under the
    discovered base. Pure arithmetic: no memory is touched and no API
    is called, so it is valid at any IRQL.

Arguments:

    PteBase - The discovered PTE array base for this boot.

    Va - The virtual address whose PTE is wanted.

Return Value:

    The virtual address of the PTE.

--*/
{
    return (volatile ULONG64*)(PteBase +
        ((((ULONG64)(ULONG_PTR)Va) >> 9) & 0x7FFFFFFFF8ULL));
}

static
_IRQL_requires_max_(HIGH_LEVEL)
VOID
PhysicalFlushWindow(
    _In_ PVOID Window
)
/*++

Routine Description:

    Invalidates the single TLB entry for the window. INVLPG clears even
    a global entry, so no CR3 flush is needed however the original PTE
    set the global bit. The barriers order the PTE store before the
    flush and the flush before the copy that follows.

Arguments:

    Window - The window virtual address to flush.

Return Value:

    None.

--*/
{
    KeMemoryBarrier();
    __invlpg(Window);
    KeMemoryBarrier();
}

#pragma code_seg(push)
#pragma code_seg("PAGE")

static
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
PhysicalDiscoverPteBase(
    _Out_ ULONG64* PteBase
)
/*++

Routine Description:

    Locates the kernel's self-referencing PML4 entry and derives the
    PTE array base for this boot. The live PML4 is read through a
    temporary cached mapping of the CR3 frame; the single present entry
    whose frame is the PML4 frame itself is the self-reference. The
    base is that index shifted to the PML4 position with the canonical
    sign extension, which holds because the kernel keeps the index in
    the upper half.

    Runs once at setup, on the loading thread in kernel context, so the
    CR3 read observes the kernel address space whose self-reference
    index applies boot-wide. Reading nt!MmPteBase instead would need an
    unexported global; the scan is self-contained and fails loudly when
    the layout is not what this module implements.

Arguments:

    PteBase - Receives the PTE array base for this boot.

Return Value:

    STATUS_SUCCESS with the base published. Five level paging, a
    missing mapping, zero matches, more than one match, or an index
    outside the kernel half all fail load rather than guessing a base.

--*/
{
    ULONG64 Cr3;
    PHYSICAL_ADDRESS Pml4Physical;
    PVOID Mapping;
    volatile ULONG64* Entries;
    ULONG MatchIndex;
    ULONG MatchCount;
    ULONG Index;

    if ((__readcr4() & PHYSICAL_CR4_LA57) != 0)
    {
        KmError("Five level paging is not supported\n");
        return STATUS_NOT_SUPPORTED;
    }

    //
    // CR3 carries the PML4 frame in bits 51:12; the low twelve are
    // PCID and key bits, not address.
    //

    Cr3 = (ULONG64)__readcr3();
    Pml4Physical.QuadPart = (LONGLONG)(Cr3 & PHYSICAL_PTE_PFN_MASK);

    if (Pml4Physical.QuadPart == 0)
    {
        KmError("Empty CR3\n");
        return STATUS_DATA_ERROR;
    }

    Mapping = MmMapIoSpace(Pml4Physical, PAGE_SIZE, MmCached);

    if (Mapping == NULL)
    {
        KmError("Failed to map the PML4 at 0x%I64X\n",
            (ULONG64)Pml4Physical.QuadPart);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Entries = (volatile ULONG64*)Mapping;
    MatchIndex = 0;
    MatchCount = 0;

    for (Index = 0; Index < PHYSICAL_PML4_ENTRY_COUNT; Index += 1)
    {
        ULONG64 Entry;

        Entry = Entries[Index];

        if ((Entry & PHYSICAL_PTE_PRESENT) == 0)
        {
            continue;
        }

        //
        // A PML4 entry is always a table reference, so only the frame
        // comparison matters: the entry naming the PML4 frame is the
        // self-reference.
        //

        if ((Entry & PHYSICAL_PTE_PFN_MASK) ==
            ((ULONG64)Pml4Physical.QuadPart & PHYSICAL_PTE_PFN_MASK))
        {
            MatchIndex = Index;
            MatchCount += 1;
        }
    }

    MmUnmapIoSpace(Mapping, PAGE_SIZE);

    if (MatchCount != 1)
    {
        KmError("Ambiguous PML4 self-reference - Matches=%u\n",
            MatchCount);
        return STATUS_DATA_ERROR;
    }

    if (MatchIndex < PHYSICAL_PML4_KERNEL_HALF_MIN)
    {
        KmError("Self-reference outside the kernel half - Index=0x%X\n",
            MatchIndex);
        return STATUS_DATA_ERROR;
    }

    *PteBase = PHYSICAL_VA_SIGN_EXTENSION |
        ((ULONG64)MatchIndex << 39);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PhysicalInitialize(
    VOID
)
/*++

Routine Description:

    Allocates the window, captures the PTE state and forces the PTE
    present and writable. This is the only pageable routine in the
    module and the only one that calls allocation and physical-address
    APIs.

    A contiguous page is used rather than pool so the PTE is exclusive:
    pool pages are shared, and retargeting a shared PTE would corrupt
    the neighbor. The contiguous page is page aligned by contract.

    The PTE must be a present 4K PTE. A large page here would mean the
    allocator changed granularity, and failing load is safer than
    splitting it.

Arguments:

    None.

Return Value:

    STATUS_SUCCESS with the window ready, or a failure status with
    nothing allocated and no state published.

--*/
{
    NTSTATUS Status;
    ULONG64 PteBase;
    PHYSICAL_ADDRESS Highest;
    PVOID Window;
    volatile ULONG64* Pte;
    ULONG64 Original;
    PHYSICAL_ADDRESS PtePhysical;
    PHYSICAL_ADDRESS WindowPhysical;

    PAGED_CODE();

    RtlZeroMemory(&g_PhysicalState, sizeof(g_PhysicalState));
    g_PhysicalReady = FALSE;

    Status = PhysicalDiscoverPteBase(&PteBase);

    if (!NT_SUCCESS(Status))
    {
        KmError("PTE base discovery failed - Status=%s (0x%08X)\n",
            KmStatusToString(Status), Status);
        return Status;
    }

    Highest.QuadPart = (LONGLONG)0xFFFFFFFFFFFFFFFFULL;

    Window = MmAllocateContiguousMemory(PAGE_SIZE, Highest);

    if (Window == NULL)
    {
        KmError("Failed to allocate the physical window\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Window, PAGE_SIZE);

    //
    // The window is resident non-paged memory, so its PTE is resident
    // and the read below through the discovered base cannot fault at
    // PASSIVE_LEVEL.
    //

    Pte = PhysicalPteForVa(PteBase, Window);
    Original = *Pte;

    if ((Original & PHYSICAL_PTE_PRESENT) == 0)
    {
        KmError("Window PTE not present - Pte=%p Original=0x%I64X\n",
            (PVOID)Pte, Original);
        MmFreeContiguousMemory(Window);
        return STATUS_DATA_ERROR;
    }

    if ((Original & PHYSICAL_PTE_LARGE) != 0)
    {
        KmError("Window PTE is a large page - Pte=%p Original=0x%I64X\n",
            (PVOID)Pte, Original);
        MmFreeContiguousMemory(Window);
        return STATUS_DATA_ERROR;
    }

    PtePhysical = MmGetPhysicalAddress((PVOID)Pte);

    if (PtePhysical.QuadPart == 0)
    {
        KmError("Window PTE has no physical address - Pte=%p\n",
            (PVOID)Pte);
        MmFreeContiguousMemory(Window);
        return STATUS_DATA_ERROR;
    }

    //
    // The frame named by the PTE must be the window's own frame. A
    // mismatch means the discovered base is wrong, and continuing
    // would retarget an unrelated page.
    //

    WindowPhysical = MmGetPhysicalAddress(Window);

    if ((Original & PHYSICAL_PTE_PFN_MASK) !=
        ((ULONG64)WindowPhysical.QuadPart & PHYSICAL_PTE_PFN_MASK))
    {
        KmError("Window PTE names a foreign frame - Pte=%p "
            "Original=0x%I64X WindowPa=0x%I64X\n",
            (PVOID)Pte, Original,
            (ULONG64)WindowPhysical.QuadPart);
        MmFreeContiguousMemory(Window);
        return STATUS_DATA_ERROR;
    }

    g_PhysicalState.Window = Window;
    g_PhysicalState.PteBase = PteBase;
    g_PhysicalState.Pte = Pte;
    g_PhysicalState.OriginalPte = Original;
    g_PhysicalState.PtePhysicalAddress = (ULONG64)PtePhysical.QuadPart;

    //
    // Force readable and writable up front so the hot paths only ever
    // replace the frame. Accessed and dirty are forced too, so a first
    // access through a fresh frame never takes an A/D fault inside the
    // window. The store is ordered through the same flush the hot
    // paths use.
    //

    *Pte = Original | PHYSICAL_PTE_PRESENT | PHYSICAL_PTE_WRITABLE |
        PHYSICAL_PTE_ACCESSED | PHYSICAL_PTE_DIRTY;
    PhysicalFlushWindow(Window);

    KeMemoryBarrier();
    g_PhysicalReady = TRUE;
    KeMemoryBarrier();

    KmPrint("Physical ready - Window=%p Base=0x%I64X Pte=%p PtePa=0x%I64X "
        "Original=0x%I64X\n",
        Window, PteBase, (PVOID)Pte,
        g_PhysicalState.PtePhysicalAddress, Original);

    return STATUS_SUCCESS;
}

#pragma code_seg(pop)

_Use_decl_annotations_
VOID
PhysicalUninitialize(
    VOID
)
/*++

Routine Description:

    Restores the original PTE, flushes the window and frees the page.
    Resident so the code itself never depends on paging, but still
    PASSIVE_LEVEL: the free call is only legal there. The caller
    guarantees no hot path is in flight: the restore is the last use
    of the PTE, and a concurrent copy would read through a freed page.

Arguments:

    None.

Return Value:

    None.

--*/
{
    PVOID Window;
    volatile ULONG64* Pte;
    ULONG64 Original;

    if (!g_PhysicalReady)
    {
        return;
    }

    //
    // Publish the stop before touching the PTE so a racing reader that
    // checks readiness observes the teardown. Genuine racing is still
    // a caller bug; this only narrows the window, it does not close
    // it, because no lock is legal at HIGH_LEVEL.
    //

    g_PhysicalReady = FALSE;
    KeMemoryBarrier();

    Window = g_PhysicalState.Window;
    Pte = g_PhysicalState.Pte;
    Original = g_PhysicalState.OriginalPte;

    *Pte = Original;
    PhysicalFlushWindow(Window);

    MmFreeContiguousMemory(Window);

    RtlZeroMemory(&g_PhysicalState, sizeof(g_PhysicalState));

    KmTrace("Physical released\n");
}

_Use_decl_annotations_
VOID
PhysicalSetBacking(
    ULONG64 PhysicalAddress
)
/*++

Routine Description:

    Points the window at the page frame containing the supplied byte
    physical address and flushes the stale translation. The address may
    be byte granular; only its page frame is consumed. Flag bits come
    from the captured original with present, writable, accessed and
    dirty forced on, so caching stays write-back as allocated.

    Silent and lockless: the caller serializes all window users. A call
    while the window is not initialized is a no-op.

Arguments:

    PhysicalAddress - The byte physical address to map. Only bits
        63:12 matter; bits 11:0 select the offset inside the window
        on the following copy.

Return Value:

    None.

--*/
{
    volatile ULONG64* Pte;
    ULONG64 Original;
    ULONG64 Aligned;
    PVOID Window;

    if (!g_PhysicalReady)
    {
        return;
    }

    Pte = g_PhysicalState.Pte;
    Original = g_PhysicalState.OriginalPte;
    Window = g_PhysicalState.Window;
    Aligned = PhysicalAddress & ~PHYSICAL_PTE_PAGE_OFFSET_MASK;

    *Pte = (Original & ~PHYSICAL_PTE_PFN_MASK) |
        (Aligned & PHYSICAL_PTE_PFN_MASK) |
        PHYSICAL_PTE_PRESENT | PHYSICAL_PTE_WRITABLE |
        PHYSICAL_PTE_ACCESSED | PHYSICAL_PTE_DIRTY;

    PhysicalFlushWindow(Window);
}

_Use_decl_annotations_
NTSTATUS
PhysicalRead(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    SIZE_T Size
)
/*++

Routine Description:

    Copies bytes from physical memory into the caller's buffer, one
    window backing per page. Each iteration retargets the PTE, flushes
    with INVLPG and copies the slice that falls inside the newly
    mapped frame.

    The buffer must be resident for the whole call. Nothing here probes
    it: probing can fault, and faulting is fatal at HIGH_LEVEL.

Arguments:

    PhysicalAddress - The first byte physical address to read.

    Buffer - Receives the bytes. Resident, writable for Size bytes.

    Size - Number of bytes to copy. Zero succeeds as a no-op.

Return Value:

    STATUS_SUCCESS, STATUS_INVALID_DEVICE_STATE when the window is not
    initialized, or STATUS_INVALID_PARAMETER for a null buffer with a
    nonzero size.

--*/
{
    PUCHAR Destination;
    PVOID Window;
    ULONG64 Current;
    SIZE_T Remaining;

    if (!g_PhysicalReady)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Size == 0)
    {
        return STATUS_SUCCESS;
    }

    if (Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    //
    // Cache the window locally. The window address is stable while
    // ready is set, and the caller guarantees teardown never runs
    // concurrently with a copy.
    //

    Window = g_PhysicalState.Window;
    Destination = (PUCHAR)Buffer;
    Current = PhysicalAddress;
    Remaining = Size;

    while (Remaining > 0)
    {
        SIZE_T Offset;
        SIZE_T Chunk;

        Offset = (SIZE_T)(Current & PHYSICAL_PTE_PAGE_OFFSET_MASK);
        Chunk = PAGE_SIZE - Offset;

        if (Chunk > Remaining)
        {
            Chunk = Remaining;
        }

        PhysicalSetBacking(Current & ~PHYSICAL_PTE_PAGE_OFFSET_MASK);

        RtlCopyMemory(
            Destination,
            (PUCHAR)Window + Offset,
            Chunk
        );

        Destination += Chunk;
        Current += Chunk;
        Remaining -= Chunk;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
PhysicalWrite(
    ULONG64 PhysicalAddress,
    PCVOID Buffer,
    SIZE_T Size
)
/*++

Routine Description:

    Copies bytes from the caller's buffer into physical memory, one
    window backing per page. Mirrors PhysicalRead: each iteration
    retargets the PTE, flushes with INVLPG and copies the slice that
    falls inside the newly mapped frame.

    The buffer must be resident for the whole call, for the same reason
    as the read path. The target is written with the window's
    write-back caching; a device register that needs uncached semantics
    is out of scope.

Arguments:

    PhysicalAddress - The first byte physical address to write.

    Buffer - Supplies the bytes. Resident, readable for Size bytes.

    Size - Number of bytes to copy. Zero succeeds as a no-op.

Return Value:

    STATUS_SUCCESS, STATUS_INVALID_DEVICE_STATE when the window is not
    initialized, or STATUS_INVALID_PARAMETER for a null buffer with a
    nonzero size.

--*/
{
    PCUCHAR Source;
    PVOID Window;
    ULONG64 Current;
    SIZE_T Remaining;

    if (!g_PhysicalReady)
    {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (Size == 0)
    {
        return STATUS_SUCCESS;
    }

    if (Buffer == NULL)
    {
        return STATUS_INVALID_PARAMETER;
    }

    Window = g_PhysicalState.Window;
    Source = (PCUCHAR)Buffer;
    Current = PhysicalAddress;
    Remaining = Size;

    while (Remaining > 0)
    {
        SIZE_T Offset;
        SIZE_T Chunk;

        Offset = (SIZE_T)(Current & PHYSICAL_PTE_PAGE_OFFSET_MASK);
        Chunk = PAGE_SIZE - Offset;

        if (Chunk > Remaining)
        {
            Chunk = Remaining;
        }

        PhysicalSetBacking(Current & ~PHYSICAL_PTE_PAGE_OFFSET_MASK);

        RtlCopyMemory(
            (PUCHAR)Window + Offset,
            Source,
            Chunk
        );

        Source += Chunk;
        Current += Chunk;
        Remaining -= Chunk;
    }

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
PVOID
PhysicalGetWindow(
    VOID
)
/*++

Routine Description:

    Reports the window virtual address for diagnostics.

Arguments:

    None.

Return Value:

    The window address, or NULL while uninitialized.

--*/
{
    if (!g_PhysicalReady)
    {
        return NULL;
    }

    return g_PhysicalState.Window;
}

_Use_decl_annotations_
ULONG64
PhysicalGetPtePhysicalAddress(
    VOID
)
/*++

Routine Description:

    Reports the byte physical address of the window's PTE, captured at
    setup with MmGetPhysicalAddress.

Arguments:

    None.

Return Value:

    The PTE physical address, or zero while uninitialized.

--*/
{
    if (!g_PhysicalReady)
    {
        return 0;
    }

    return g_PhysicalState.PtePhysicalAddress;
}

_Use_decl_annotations_
BOOLEAN
PhysicalIsReady(
    VOID
)
/*++

Routine Description:

    Reports whether the window is initialized.

Arguments:

    None.

Return Value:

    TRUE while PhysicalInitialize succeeded and PhysicalUninitialize
    has not yet run.

--*/
{
    return g_PhysicalReady;
}

#else

//
// Non x64 stub. The window relies on the x64 self map and INVLPG, so
// it is x64 only.
//

_Use_decl_annotations_
NTSTATUS
PhysicalInitialize(
    VOID
)
{
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
VOID
PhysicalUninitialize(
    VOID
)
{
}

_Use_decl_annotations_
VOID
PhysicalSetBacking(
    ULONG64 PhysicalAddress
)
{
    UNREFERENCED_PARAMETER(PhysicalAddress);
}

_Use_decl_annotations_
NTSTATUS
PhysicalRead(
    ULONG64 PhysicalAddress,
    PVOID Buffer,
    SIZE_T Size
)
{
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);

    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
NTSTATUS
PhysicalWrite(
    ULONG64 PhysicalAddress,
    PCVOID Buffer,
    SIZE_T Size
)
{
    UNREFERENCED_PARAMETER(PhysicalAddress);
    UNREFERENCED_PARAMETER(Buffer);
    UNREFERENCED_PARAMETER(Size);

    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
PVOID
PhysicalGetWindow(
    VOID
)
{
    return NULL;
}

_Use_decl_annotations_
ULONG64
PhysicalGetPtePhysicalAddress(
    VOID
)
{
    return 0;
}

_Use_decl_annotations_
BOOLEAN
PhysicalIsReady(
    VOID
)
{
    return FALSE;
}

#endif
