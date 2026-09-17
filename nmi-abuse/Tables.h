#pragma once

#include <ntifs.h>

/*++

Module Name:

    Tables.h

Abstract:

    This module declares the descriptor state for the experiment.

    Design decision, per review: the private GDT is gone. The crafted
    register block reuses the native GDTR verbatim, so LGDT reloads the
    Windows GDT that is already valid on this CPU. Only the IDT is
    custom, and only TR is crafted.

    The TR trick: Tr is the null selector (0x0000). The KiRestore
    sequence first computes GdtBase + Tr and clears the busy bit at
    [rax+5]:

        movzx eax, word ptr [rcx+70h]   ; eax = 0
        add rax, [rcx+58h]              ; rax = GdtBase
        and byte ptr [rax+5], 0FDh      ; null descriptor byte 5 &= ~2

    The null descriptor is all zeros, so the AND is a no-op and always
    touches writable, resident GDT memory. The following LTR 0 then
    faults deterministically with #GP(0): a null selector can never be
    loaded into TR. That #GP, vector 13 with error code 0, is the
    expected fault the custom IDT handles by entering the APIC_WRITE
    window. Any other vector, any other error code, or a fault whose
    RIP is not the LTR is fatal.

    The previously loaded (native) TSS stays active throughout, because
    the faulting LTR never completes. Its IST configuration therefore
    still matters: every custom gate uses IST index 0 so handling stays
    on the current thread stack, which is what makes frame surgery and
    stack restoration possible.

--*/

//
// The faulting selector. Null, for the reason above.
//

#define TABLES_TR_FAULTING              0x0000

//
// The Cr8 value the block carries. This is a TPR value, not an IRQL:
// CR8 implements bits 3:0 only, and loading anything with bits 63:4
// set raises #GP. HIGH_LEVEL as an IRQL constant is 31 (0x1F), which
// would fault inside the gadget while the native IDT is still loaded.
// 15 is the highest representable TPR and masks every maskable vector,
// which is the entire intent.
//

#define TABLES_CR8_BLOCK_ALL            15ULL

//
// One IDT: 256 sixteen-byte gates, sixteen-byte aligned, resident.
//

#define TABLES_IDT_COUNT                256
//
// One IDT: 256 sixteen-byte gates, sixteen-byte aligned, resident.
//

#define TABLES_IDT_COUNT                256
#define TABLES_IDT_BYTES                (TABLES_IDT_COUNT * 16)

#define TABLES_POOL_TAG                 'bTmN'

/*++

Structure Description:

    The sixteen-byte native descriptor shape used by _KDESCRIPTOR in
    Entry.cpp: three pad words, the limit, then the base. Kept here so
    the prepared block and the capture code agree byte for byte with
    the KiRestore offsets (GDTR limit at +0x56, IDTR limit at +0x66).

--*/

typedef struct _TABLES_DESCRIPTOR
{
    USHORT Pad[3];
    USHORT Limit;
    VOID* Base;
} TABLES_DESCRIPTOR, *PTABLES_DESCRIPTOR;

C_ASSERT(sizeof(TABLES_DESCRIPTOR) == 0x10);

/*++

Structure Description:

    The KSPECIAL_REGISTERS block KiRestoreProcessorControlState consumes
    in RCX. Layout matches the kernel structure exactly; only the fields
    KiRestore reads before the fault matter (Cr0/Cr3/Cr4/Cr8, the two
    descriptors, Tr), but the whole block is carried so a debugger dump
    of RCX reads coherently.

--*/

typedef struct _TABLES_SPECIAL_REGISTERS
{
    ULONGLONG Cr0;
    ULONGLONG Cr2;
    ULONGLONG Cr3;
    ULONGLONG Cr4;
    ULONGLONG KernelDr0;
    ULONGLONG KernelDr1;
    ULONGLONG KernelDr2;
    ULONGLONG KernelDr3;
    ULONGLONG KernelDr6;
    ULONGLONG KernelDr7;
    TABLES_DESCRIPTOR Gdtr;
    TABLES_DESCRIPTOR Idtr;
    USHORT Tr;
    USHORT Ldtr;
    ULONG MxCsr;
    ULONGLONG DebugControl;
    ULONGLONG LastBranchToRip;
    ULONGLONG LastBranchFromRip;
    ULONGLONG LastExceptionToRip;
    ULONGLONG LastExceptionFromRip;
    ULONGLONG Cr8;
    ULONGLONG MsrGsBase;
    ULONGLONG MsrGsSwap;
    ULONGLONG MsrStar;
    ULONGLONG MsrLStar;
    ULONGLONG MsrCStar;
    ULONGLONG MsrSyscallMask;
    ULONGLONG Xcr0;
    ULONGLONG MsrFsBase;
    ULONGLONG SpecialPadding0;
} TABLES_SPECIAL_REGISTERS, *PTABLES_SPECIAL_REGISTERS;

/*++

Structure Description:

    One sixteen-byte x64 interrupt gate. Offset is split 16/16/32;
    Selector must be a valid kernel code selector in the loaded GDT;
    Ist is the IST index (0 here); TypeAttr is 0x8E (present, DPL 0,
    interrupt gate).

--*/

typedef struct _TABLES_IDT_GATE
{
    USHORT OffsetLow;
    USHORT Selector;
    UCHAR Ist;
    UCHAR TypeAttr;
    USHORT OffsetMid;
    ULONG OffsetHigh;
    ULONG Reserved;
} TABLES_IDT_GATE, *PTABLES_IDT_GATE;

C_ASSERT(sizeof(TABLES_IDT_GATE) == 0x10);

/*++

Structure Description:

    Lifetime state for one pinned worker. Idt is the custom table;
    Block is the RCX argument; the Native* fields are captured on the
    pinned CPU and are both the LGDT/LIDT source of no change and the
    teardown restore source. All storage is non-paged and outlives every
    cycle.

--*/

typedef struct _TABLES_STATE
{
    PTABLES_IDT_GATE Idt;
    PTABLES_SPECIAL_REGISTERS Block;
    USHORT NativeLimit;
    ULONG64 NativeGdtBase;
    USHORT NativeIdtLimit;
    ULONG64 NativeIdtBase;
    USHORT NativeTr;
    USHORT NativeCs;
    USHORT NativeSs;
} TABLES_STATE, *PTABLES_STATE;

//
// NativeTr is always zero: there is no MSVC intrinsic that reads STR,
// and none is needed. The crafted LTR faults on every cycle, so the
// previously loaded TR stays active from the first entry to the last
// teardown and neither path ever reloads it. The field exists so the
// log line reads honestly (0x0) rather than implying a capture.
//

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
TablesInitialize(
    _Out_ PTABLES_STATE State,
    _In_ const PROCESSOR_NUMBER* Processor
);

_IRQL_requires_(PASSIVE_LEVEL)
VOID
TablesUninitialize(
    _Inout_ PTABLES_STATE State
);
