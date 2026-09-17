#pragma once

#include <ntifs.h>

/*++

Module Name:

    Asm.h

Abstract:

    This module declares the assembly surface in Asm.asm: the IDT stubs,
    the direct-thread protocol and the assembly-owned shared variables
    the C++ side fills before thread creation.

    Direct-thread protocol: the worker creates the system thread with
    StartRoutine set to the resolved KiRestoreProcessorControlState
    address and StartContext set to the prepared block. x64 thread
    startup calls StartRoutine(StartContext), so the thread is born
    inside the gadget with RCX already holding the block; no C++
    routine ever runs on it. Every cycle ends in the NMI teardown,
    which patches its own trap frame into a reentry frame
    (RIP = routine, RCX = block, RSP = stashed entry RSP) and executes
    IRETQ. The thread therefore never leaves the gadget except to die:
    the stop paths restore the natives and call PsTerminateSystemThread
    on the clean thread stack.

    The entry RSP is constant across cycles because the gadget uses no
    stack between its entry and the faulting LTR. The #GP stub stashes
    the interrupted (entry) RSP into g_AsmEntryRsp on its way into the
    APIC_WRITE window; the NMI teardown consumes it. An NMI that lands
    before the first stash (a foreign NMI inside the first few
    instructions) takes the transparent path instead: one compensating
    ICR write and an IRETQ back to the interrupted context, with no
    state changed.

    All assembly code and data are resident (default .text/.data, never
    PAGE): every stub runs with the custom IDT loaded, where a page
    fault would be fatal rather than serviceable.

--*/

EXTERN_C_START

//
// IDT stub addresses, for gate construction. Never called from C++.
//

ULONG64
AsmNmiStubAddress(
    VOID
);

ULONG64
AsmGpStubAddress(
    VOID
);

ULONG64
AsmMcStubAddress(
    VOID
);

//
// Address of the default thunk for one vector (0..255). Each thunk
// normalizes to [vector][error][frame] and lands in a common fatal
// handler, so the exact unexpected vector is always known.
//

ULONG64
AsmDefaultThunkAddress(
    _In_ ULONG Vector
);

//
// Marker addresses for offline classification and debugging. The NMI
// stub compares RIP against these labels directly (union of both APIC
// modes, so a hypothetical mode flap cannot misclassify); C++ never
// dispatches on them.
//

ULONG64
AsmDwellStartAddress(
    VOID
);

ULONG64
AsmDwellEndAddress(
    VOID
);

ULONG64
AsmApicWriteXapicAddress(
    VOID
);

ULONG64
AsmApicWriteX2apicAddress(
    VOID
);

//
// Assembly-owned shared state, filled by the worker before thread
// creation (except EntryRsp and CycleCount, which the stubs own). The
// ICR addresses come from the APIC module; the descriptor fields and
// the block/routine pair from the tables and restore modules; the
// event buffer and stop flag from the worker.
//

extern volatile ULONG g_AsmApicMode;
extern ULONG64 g_AsmXapicIcrLow;
extern ULONG64 g_AsmXapicIcrHigh;
extern USHORT g_AsmNativeGdtrLimit;
extern ULONG64 g_AsmNativeGdtrBase;
extern USHORT g_AsmNativeIdtrLimit;
extern ULONG64 g_AsmNativeIdtrBase;
extern USHORT g_AsmNativeCs;
extern USHORT g_AsmNativeSs;
extern ULONG64 g_AsmEventBuffer;
extern LONG volatile* g_AsmStopFlag;
extern ULONG64 g_AsmBlock;
extern ULONG64 g_AsmRoutine;
extern ULONG64 g_AsmEntryRsp;
extern ULONG64 g_AsmCycleCount;
extern ULONG g_AsmStopDrain;
extern ULONG64 g_AsmDwellIters;
extern ULONG64 g_AsmIssueSeq;
extern ULONG64 g_AsmUpTsc;
extern ULONG64 g_AsmMetricBuffer;

/*++

Structure Description:

    The ten-byte GDTR/IDTR read layout (limit then base). AsmReadGdtr
    fills this; the tables module spreads it into its state. Packed:
    SGDT stores the two fields contiguously.

--*/

#pragma pack(push, 1)
typedef struct _ASM_DESCRIPTOR_RAW
{
    USHORT Limit;
    ULONG64 Base;
} ASM_DESCRIPTOR_RAW, *PASM_DESCRIPTOR_RAW;
#pragma pack(pop)

C_ASSERT(sizeof(ASM_DESCRIPTOR_RAW) == 10);

//
// Privileged reads this MSVC exposes no intrinsic for. SGDT is the
// only one the experiment needs: CS/SS come from RtlCaptureContext,
// and TR is intentionally never read.
//

VOID
AsmReadGdtr(
    _Out_ PASM_DESCRIPTOR_RAW Gdtr
);

//
// Unmangled recorder forwarder, implemented in Trace.cpp over
// KmEventRecord. The stubs call this; C++ code uses KmEventRecord.
//

VOID
AsmRecordEvent(
    _In_opt_ PVOID Buffer,
    _In_ ULONG Event,
    _In_ ULONG Vector,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Rsp,
    _In_ ULONG64 Cr8,
    _In_ ULONG64 Detail
);

//
// Unmangled per-delivery metric forwarder, implemented in Trace.cpp
// over KmMetricRecord. The NMI stub calls this once per delivery with
// the already-classified Flags; C++ code uses KmMetricRecord.
//

_IRQL_requires_max_(HIGH_LEVEL)
VOID
AsmMetricRecord(
    _In_opt_ PVOID Buffer,
    _In_ ULONG64 Rip,
    _In_ ULONG64 Rsp,
    _In_ ULONG Flags
);

EXTERN_C_END
