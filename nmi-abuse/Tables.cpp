#include "Tables.h"
#include "Debug.h"
#include "Asm.h"

#include <intrin.h>

/*++

Module Name:

    Tables.cpp (part 1)

Abstract:

    Gate writer and native capture. The initializer that wires them
    together follows in part 2.

--*/

#pragma code_seg(push)
#pragma code_seg("PAGE")

#if defined(_AMD64_)

static
VOID
TablesWriteGate(
    _Out_ PTABLES_IDT_GATE Gate,
    _In_ ULONG64 Handler,
    _In_ USHORT Selector
)
/*++

Routine Description:

    Fills one interrupt gate: present, DPL 0, type 0xE, IST 0. Staying
    on the current stack (IST 0) is load bearing: the teardown discards
    the fault and NMI frames by switching RSP back to the saved thread
    stack, which only works when every frame is on that stack.

Arguments:

    Gate - The gate to fill.

    Handler - Handler RIP (an Asm.asm stub).

    Selector - Kernel code selector from the loaded GDT.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    Gate->OffsetLow = (USHORT)(Handler & 0xFFFFULL);
    Gate->Selector = Selector;
    Gate->Ist = 0;
    Gate->TypeAttr = 0x8EU;
    Gate->OffsetMid = (USHORT)((Handler >> 16) & 0xFFFFULL);
    Gate->OffsetHigh = (ULONG)((Handler >> 32) & 0xFFFFFFFFULL);
    Gate->Reserved = 0;
}

_Use_decl_annotations_
NTSTATUS
TablesInitialize(
    PTABLES_STATE State,
    const PROCESSOR_NUMBER* Processor
)
/*++

Routine Description:

    Captures the native descriptor state on the pinned CPU, builds the
    custom IDT and prepares the RCX block. Must run on the worker thread
    after it pinned itself: SGDT/SIDT/STR/CS/SS describe the executing
    CPU, and the block must describe that same CPU.

    The IDT starts as 256 fatal gates, then vector 2 (NMI), vector 13
    (#GP, the expected LTR fault) and vector 18 (#MC, still possible at
    HIGH_LEVEL) get their real stubs. Everything else bugchecks: an
    unexpected vector under the custom IDT means the experiment, not
    Windows, is at fault.

    The block reuses the native GDTR verbatim, points the IDTR at the
    custom table, sets Tr to the null selector and Cr8 to HIGH_LEVEL.
    Cr0/Cr3/Cr4 are the live values: KiRestore rewrites them with
    identical content, which keeps the MMU untouched while still
    stepping through the whole restore prefix.

Arguments:

    State - Receives the lifetime state. Zeroed first.

    Processor - The pinned processor, for diagnostics only.

Return Value:

    STATUS_SUCCESS or STATUS_INSUFFICIENT_RESOURCES.

--*/
{
    PTABLES_IDT_GATE Idt;
    PTABLES_SPECIAL_REGISTERS Block;
    ULONG Index;

    PAGED_CODE();

    RtlZeroMemory(State, sizeof(*State));

    Idt = (PTABLES_IDT_GATE)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        TABLES_IDT_BYTES,
        TABLES_POOL_TAG
    );

    if (Idt == NULL)
    {
        KmError("Failed to allocate the custom IDT\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Block = (PTABLES_SPECIAL_REGISTERS)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(*Block),
        TABLES_POOL_TAG
    );

    if (Block == NULL)
    {
        KmError("Failed to allocate the special register block\n");
        ExFreePoolWithTag(Idt, TABLES_POOL_TAG);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Idt, TABLES_IDT_BYTES);
    RtlZeroMemory(Block, sizeof(*Block));

    //
    // Capture. __sidt stores limit then base (10 bytes); GDTR comes
    // from AsmReadGdtr, because this MSVC exposes no _sgdt intrinsic
    // and the read is privileged either way. CS/SS come from
    // RtlCaptureContext for the same toolchain reason. TR is
    // deliberately not captured (see Tables.h): the crafted LTR always
    // faults, so the previously loaded TR stays active and is never
    // reloaded by either path.
    //

    {
        ASM_DESCRIPTOR_RAW GdtrRaw;
        struct { USHORT Limit; ULONG64 Base; } IdtrRaw;
        CONTEXT Captured;

        GdtrRaw.Limit = 0;
        GdtrRaw.Base = 0;
        IdtrRaw.Limit = 0;
        IdtrRaw.Base = 0;

        AsmReadGdtr(&GdtrRaw);
        __sidt(&IdtrRaw);

        RtlZeroMemory(&Captured, sizeof(Captured));
        RtlCaptureContext(&Captured);

        State->NativeGdtBase = GdtrRaw.Base;
        State->NativeLimit = GdtrRaw.Limit;
        State->NativeIdtBase = IdtrRaw.Base;
        State->NativeIdtLimit = IdtrRaw.Limit;
        State->NativeTr = 0;
        State->NativeCs = (USHORT)Captured.SegCs;
        State->NativeSs = (USHORT)Captured.SegSs;
    }

    if ((State->NativeGdtBase < 0xFFFF800000000000ULL) ||
        (State->NativeIdtBase < 0xFFFF800000000000ULL) ||
        (State->NativeCs == 0))
    {
        KmError("Implausible native descriptor state - "
            "GdtBase=0x%I64X IdtBase=0x%I64X Cs=0x%X\n",
            State->NativeGdtBase, State->NativeIdtBase,
            (ULONG)State->NativeCs);
        ExFreePoolWithTag(Block, TABLES_POOL_TAG);
        ExFreePoolWithTag(Idt, TABLES_POOL_TAG);
        return STATUS_DATA_ERROR;
    }

    //
    // IDT: fatal everywhere first, through the per-vector thunks, so an
    // unexpected delivery always reports its exact vector before the
    // bugcheck.
    //

    for (Index = 0; Index < TABLES_IDT_COUNT; Index += 1)
    {
        TablesWriteGate(
            &Idt[Index],
            AsmDefaultThunkAddress(Index),
            State->NativeCs
        );
    }

    //
    // Then the three live gates. NMI has no error code; #GP does and is
    // validated by the stub (RIP must be the LTR, code must be 0); #MC
    // has no error code and bugchecks with the machine-check code.
    //

    TablesWriteGate(&Idt[2], AsmNmiStubAddress(), State->NativeCs);
    TablesWriteGate(&Idt[13], AsmGpStubAddress(), State->NativeCs);
    TablesWriteGate(&Idt[18], AsmMcStubAddress(), State->NativeCs);

    //
    // Block: live control registers, native GDT, custom IDT, faulting
    // TR, HIGH_LEVEL. MxCsr is the live value; the debug/MSR fields
    // stay zero because KiRestore never reads them on this path.
    //

    Block->Cr0 = __readcr0();
    Block->Cr2 = __readcr2();
    Block->Cr3 = __readcr3();
    Block->Cr4 = __readcr4();
    Block->MxCsr = (ULONG)_mm_getcsr();

    Block->Gdtr.Pad[0] = 0;
    Block->Gdtr.Pad[1] = 0;
    Block->Gdtr.Pad[2] = 0;
    Block->Gdtr.Limit = State->NativeLimit;
    Block->Gdtr.Base = (PVOID)(ULONG_PTR)State->NativeGdtBase;

    Block->Idtr.Pad[0] = 0;
    Block->Idtr.Pad[1] = 0;
    Block->Idtr.Pad[2] = 0;
    Block->Idtr.Limit = (USHORT)(TABLES_IDT_BYTES - 1);
    Block->Idtr.Base = (PVOID)Idt;

    Block->Tr = TABLES_TR_FAULTING;
    Block->Ldtr = 0;
    Block->Cr8 = TABLES_CR8_BLOCK_ALL;

    State->Idt = Idt;
    State->Block = Block;

    KmPrint("Tables ready - Cpu=%u:%u GdtBase=0x%I64X Idt=%p Block=%p "
        "Cs=0x%X Tr=0x%X->0x%X\n",
        (ULONG)Processor->Group, (ULONG)Processor->Number,
        State->NativeGdtBase, Idt, Block,
        (ULONG)State->NativeCs, (ULONG)State->NativeTr,
        (ULONG)TABLES_TR_FAULTING);

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
VOID
TablesUninitialize(
    PTABLES_STATE State
)
/*++

Routine Description:

    Frees the IDT and the block. Safe to call after a failed
    TablesInitialize. Must run at PASSIVE_LEVEL with the experiment
    stopped: the custom IDT may be referenced by nothing at this point,
    which the worker guarantees by restoring the native IDT before it
    exits its last cycle.

Arguments:

    State - The lifetime state.

Return Value:

    None.

--*/
{
    PAGED_CODE();

    if (State->Block != NULL)
    {
        ExFreePoolWithTag(State->Block, TABLES_POOL_TAG);
        State->Block = NULL;
    }

    if (State->Idt != NULL)
    {
        ExFreePoolWithTag(State->Idt, TABLES_POOL_TAG);
        State->Idt = NULL;
    }

    KmTrace("Tables released\n");
}

#pragma code_seg(pop)

#else

//
// Non x64 stub. Descriptor capture uses SGDT/SIDT/STR/CS and the block
// feeds an x64-only restore routine.
//

_Use_decl_annotations_
NTSTATUS
TablesInitialize(
    PTABLES_STATE State,
    const PROCESSOR_NUMBER* Processor
)
{
    UNREFERENCED_PARAMETER(Processor);

    RtlZeroMemory(State, sizeof(*State));
    return STATUS_NOT_SUPPORTED;
}

_Use_decl_annotations_
VOID
TablesUninitialize(
    PTABLES_STATE State
)
{
    UNREFERENCED_PARAMETER(State);
}

#endif
