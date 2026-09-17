; /*++
;
; Module Name:
;
;     Asm.asm (part 1: shared state, direct-thread protocol)
;
; Abstract:
;
;     Assembly-owned shared variables, stub address getters and the
;     direct-thread protocol. Later parts add the APIC_WRITE window, the
;     NMI/#GP/default stubs and the teardown paths.
;
;     Direct-thread: the system thread is created with StartRoutine set
;     to KiRestoreProcessorControlState and StartContext set to the
;     block, so it is born inside the gadget with RCX already holding
;     the block. Each cycle ends in the NMI teardown, which patches its
;     own trap frame into a reentry frame (RIP = routine, RCX = block,
;     RSP = stashed entry RSP) and executes IRETQ. The entry RSP is
;     constant across cycles because the gadget uses no stack between
;     its entry and the faulting LTR; the #GP stub stashes it into
;     g_AsmEntryRsp on its way into the APIC_WRITE window.
;
;     XMM state is deliberately not preserved: no code that runs under
;     the custom IDT (KiRestore tail, these stubs, the APIC_WRITE window)
;     has live XMM state. The C recorder may use XMM internally; that is
;     fine because there is nothing to corrupt out here.
;
;     Everything in this file is resident (.text/.data, never PAGE). A
;     page fault under the custom IDT would be fatal, not serviceable.
;
; --*/

.CODE

; ---------------------------------------------------------------------
; External services.
; ---------------------------------------------------------------------

EXTERN AsmRecordEvent:PROC
EXTERN KeBugCheckEx:PROC
EXTERN PsTerminateSystemThread:PROC

; ---------------------------------------------------------------------
; Assembly-owned shared state. The C++ side fills everything except
; EntryRsp and CycleCount before thread creation; the stubs own those
; two (single writer each: the #GP stub stashes, the NMI teardown
; counts).
; ---------------------------------------------------------------------

.DATA

PUBLIC g_AsmApicMode
g_AsmApicMode       DWORD 0             ; 0 = xAPIC, 1 = x2APIC

PUBLIC g_AsmXapicIcrLow
g_AsmXapicIcrLow    QWORD 0             ; mapped ICR low address (xAPIC)

PUBLIC g_AsmXapicIcrHigh
g_AsmXapicIcrHigh   QWORD 0             ; mapped ICR high address (xAPIC)

PUBLIC g_AsmNativeGdtrLimit
g_AsmNativeGdtrLimit WORD 0

PUBLIC g_AsmNativeGdtrBase
g_AsmNativeGdtrBase QWORD 0

PUBLIC g_AsmNativeIdtrLimit
g_AsmNativeIdtrLimit WORD 0

PUBLIC g_AsmNativeIdtrBase
g_AsmNativeIdtrBase QWORD 0

PUBLIC g_AsmNativeCs
g_AsmNativeCs       WORD 0

PUBLIC g_AsmNativeSs
g_AsmNativeSs       WORD 0

PUBLIC g_AsmEventBuffer
g_AsmEventBuffer    QWORD 0             ; PKM_EVENT_BUFFER, may be 0

PUBLIC g_AsmStopFlag
g_AsmStopFlag       QWORD 0             ; LONG volatile *, may be 0

PUBLIC g_AsmBlock
g_AsmBlock          QWORD 0             ; RCX argument, reset every entry

PUBLIC g_AsmRoutine
g_AsmRoutine        QWORD 0             ; reentry RIP (the gadget)

PUBLIC g_AsmEntryRsp
g_AsmEntryRsp       QWORD 0             ; stashed gadget-entry RSP, 0 until set

PUBLIC g_AsmCycleCount
g_AsmCycleCount     QWORD 0             ; consumed-NMI cycles

.CODE

; ---------------------------------------------------------------------
; Privileged reads with no MSVC intrinsic. SGDT stores limit then base
; (10 bytes) into the caller's buffer.
; ---------------------------------------------------------------------

PUBLIC AsmReadGdtr
AsmReadGdtr PROC                        ; RCX = 10-byte buffer
    sgdt FWORD PTR [rcx]
    ret
AsmReadGdtr ENDP

; ---------------------------------------------------------------------
; Stub address getters. The C++ tables module calls these to fill IDT
; gates; they are never entered from C++.
; ---------------------------------------------------------------------

PUBLIC AsmNmiStubAddress
AsmNmiStubAddress PROC
    lea rax, [AsmNmiStub]
    ret
AsmNmiStubAddress ENDP

PUBLIC AsmGpStubAddress
AsmGpStubAddress PROC
    lea rax, [AsmGpStub]
    ret
AsmGpStubAddress ENDP

PUBLIC AsmMcStubAddress
AsmMcStubAddress PROC
    lea rax, [AsmMcStub]
    ret
AsmMcStubAddress ENDP

; /*++
;
; Part 2: APIC_WRITE window.
;
; Two loops, one per APIC mode, each shaped identically:
;
;     ICR write
;   Committed:                      ; <-- marker: write has completed
;     pause x 100000
;     stop check (unload path)
;     jmp ICR write
;   End:                            ; <-- marker: interval end
;
; The NMI handler compares the interrupted RIP against [Committed, End)
; of the active mode. Inside means the self-NMI was requested and the
; core is spinning; that delivery is consumed as the expected one.
; Below Committed means the NMI arrived before any request completed,
; so it must be foreign and a single compensating ICR write is issued
; before teardown.
;
; The stop check reads g_AsmStopFlag once per batch. When set, the loop
; exits through the GP stop path (part 4), which restores the natives
; and terminates the thread on its clean stack. Without it, an unload
; during a quiet window with no NMI traffic would wait forever.
;
; The pause count is a resend interval in instructions, not a timeout:
; each batch reissues exactly one request.
;
; --*/

; Single compensating ICR write, shared by the foreign-NMI path.
; Clobbers RAX only. Mode is read fresh so a (hypothetical) mode flap
; between setup and delivery still does the right write.

AsmSingleSelfNmi PROC
    cmp DWORD PTR [g_AsmApicMode], 1
    je @@x2
    ; xAPIC: high = 0 (self shorthand ignores destination), then low.
    mov rax, [g_AsmXapicIcrHigh]
    mov DWORD PTR [rax], 0
    mov rax, [g_AsmXapicIcrLow]
    mov DWORD PTR [rax], 40400h
    ret
@@x2:
    mov ecx, 830h
    xor edx, edx
    mov eax, 40400h
    wrmsr
    ret
AsmSingleSelfNmi ENDP

; xAPIC resend loop. Entered by the #GP stub with the #GP frame beneath.
; The Committed/End markers are global (::) labels: PUBLIC cannot name
; a procedure-scoped label, and the NMI handler in this same file
; compares RIP against exactly these addresses.

PUBLIC AsmApicWriteXapic
PUBLIC AsmApicXapicCommitted
PUBLIC AsmApicXapicEnd
AsmApicWriteXapic PROC
@@issue:
    mov rax, [g_AsmXapicIcrHigh]
    mov DWORD PTR [rax], 0
    mov rax, [g_AsmXapicIcrLow]
    mov DWORD PTR [rax], 40400h
AsmApicXapicCommitted::
    mov ecx, 100000
@@spin:
    pause
    dec ecx
    jnz @@spin
    ; Stop check, once per batch.
    mov rax, [g_AsmStopFlag]
    test rax, rax
    jz @@issue
    cmp DWORD PTR [rax], 0
    jne AsmGpTeardownStop
    jmp @@issue
AsmApicXapicEnd::
    int 3                          ; pure marker, never reached
AsmApicWriteXapic ENDP

; x2APIC resend loop. Same shape, MSR instead of MMIO.

PUBLIC AsmApicWriteX2apic
PUBLIC AsmApicX2apicCommitted
PUBLIC AsmApicX2apicEnd
AsmApicWriteX2apic PROC
@@issue:
    mov ecx, 830h
    xor edx, edx
    mov eax, 40400h
    wrmsr
AsmApicX2apicCommitted::
    mov ecx, 100000
@@spin:
    pause
    dec ecx
    jnz @@spin
    mov rax, [g_AsmStopFlag]
    test rax, rax
    jz @@issue
    cmp DWORD PTR [rax], 0
    jne AsmGpTeardownStop
    jmp @@issue
AsmApicX2apicEnd::
    int 3                          ; pure marker, never reached
AsmApicWriteX2apic ENDP

; /*++
;
; Part 3: record macro, native restore, NMI stub.
;
; NMI frame (no error code), RSP on entry points at RIP:
;
;     [RSP+00h] RIP      (interrupted address)
;     [RSP+08h] CS
;     [RSP+10h] RFLAGS
;     [RSP+18h] RSP      (interrupted stack pointer)
;     [RSP+20h] SS
;
; Event numbers match Trace.h (guarded by C_ASSERTs beside the C
; wrapper): ExpectedFault 6, IcrPostWrite 7, NmiEntry 8,
; NativeTablesRestored 9, UnexpectedFault 12.
;
; --*/

; DO_RECORD: inline AsmRecordEvent call. The caller must have pushed
; rax, rcx, rdx, r8, r9, r10, r11, rbx (in that order) and set RBX to a
; stable anchor (usually the trap frame): the macro uses R11 as scratch
; and RAX for stack arguments, both caller-saved on its stack. RBX is
; callee-saved, so it survives the call. Every operand is evaluated
; after the stack switch, so memory operands must hang off RBX (or
; RIP/.data), never off RSP.

DO_RECORD MACRO _buf, _evt, _vec, _rip, _rspv, _cr8v, _detail
    mov r11, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 48h
    mov rcx, _buf
    mov edx, _evt
    mov r8d, _vec
    mov r9, _rip
    mov rax, _rspv
    mov [rsp+20h], rax
    mov rax, _cr8v
    mov [rsp+28h], rax
    mov rax, _detail
    mov [rsp+30h], rax
    call AsmRecordEvent
    mov rsp, r11
ENDM

; AsmRestoreNatives: LIDT/LGDT native, CR8 = PASSIVE. Clobbers RAX and
; flags only, uses no calls, so it is safe at any stack alignment with
; RBX (or any other register) holding live state across it. The two
; teardown paths share it; each patches its own frame afterwards.

AsmRestoreNatives PROC
    sub rsp, 16
    mov ax, [g_AsmNativeIdtrLimit]
    mov [rsp], ax
    mov rax, [g_AsmNativeIdtrBase]
    mov [rsp+2], rax
    lidt FWORD PTR [rsp]
    mov ax, [g_AsmNativeGdtrLimit]
    mov [rsp], ax
    mov rax, [g_AsmNativeGdtrBase]
    mov [rsp+2], rax
    lgdt FWORD PTR [rsp]
    add rsp, 16
    ; Ordinary interrupts may be pending: they must find the native
    ; IDT, which they now do. Lowering CR8 unmasks them.
    xor eax, eax
    mov cr8, rax
    ret
AsmRestoreNatives ENDP

; AsmTerminateSelf: shared stop tail, entered by JMP after the caller
; restored the natives. Records the stop, then terminates the thread on
; its clean entry stack: native IDT, CR8 passive, ordinary kernel code
; again, so the call is an ordinary call. Never returns.

AsmTerminateSelf PROC
    mov rax, cr8
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@die
    mov rdx, [g_AsmRoutine]
    mov r8, [g_AsmBlock]
    DO_RECORD rcx, 11, 0FFFFFFFFh, rdx, r8, rax, 0
@@die:
    mov rsp, [g_AsmEntryRsp]
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 20h
    xor ecx, ecx                   ; STATUS_SUCCESS
    call PsTerminateSystemThread
    int 3
AsmTerminateSelf ENDP

; AsmNmiStub: vector 2. Two paths:
;
; Transparent (no entry RSP stashed yet): the #GP stub has not run, so
; this NMI landed in the first instructions of the first cycle and no
; request of ours could have completed: it is foreign. Issue one
; compensating request and IRETQ back to the interrupted context
; unchanged. Execution continues into the #GP stub, which stashes and
; enters the window; the compensation arrives later via the native IDT.
;
; Teardown (stashed): decide expected vs foreign by RIP interval. In
; the window the delivery is consumed as our own request; outside it a
; single compensating ICR write covers the consumed foreign NMI (with
; the documented coalescing bound). Then restore the natives and IRETQ
; directly back into the gadget: RIP = routine, RCX = block,
; RSP = stashed entry RSP. The interrupted context is abandoned.

PUBLIC AsmNmiStub
AsmNmiStub PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbx
    mov rbx, rsp
    add rbx, 64                    ; RBX -> NMI frame (RIP)
    mov rax, cr8
    ; Record entry. Detail is the interrupted RCX (pushed value).
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@norec1
    DO_RECORD rcx, 8, 2, QWORD PTR [rbx], QWORD PTR [rbx+24], rax, QWORD PTR [rbx-56]
@@norec1:
    cmp QWORD PTR [g_AsmEntryRsp], 0
    je @@transparent
    ; Interval check on the interrupted RIP.
    mov r10, [rbx]
    cmp DWORD PTR [g_AsmApicMode], 1
    je @@x2
    lea rax, [AsmApicXapicCommitted]
    lea rcx, [AsmApicXapicEnd]
    jmp @@cmp
@@x2:
    lea rax, [AsmApicX2apicCommitted]
    lea rcx, [AsmApicX2apicEnd]
@@cmp:
    cmp r10, rax
    jb @@foreign
    cmp r10, rcx
    jae @@foreign
    jmp @@teardown
@@transparent:
    call AsmSingleSelfNmi          ; clobbers rax, rcx, rdx; RBX kept
    pop rbx
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    pop rax
    iretq
@@foreign:
    ; Outside the marker window with the protocol up: this delivery is
    ; not our own request, so it is foreign and now consumed. One
    ; compensating request keeps Windows whole, within the documented
    ; coalescing bound.
    call AsmSingleSelfNmi          ; clobbers rax, rcx, rdx; RBX kept
@@teardown:
    call AsmRestoreNatives         ; clobbers rax only; RBX kept
    ; Record the restore. Detail is the native IDT base now in force.
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@norec2
    mov rax, cr8
    DO_RECORD rcx, 9, 2, QWORD PTR [rbx], QWORD PTR [rbx+24], rax, QWORD PTR [g_AsmNativeIdtrBase]
@@norec2:
    lock inc QWORD PTR [g_AsmCycleCount]
    ; Stop terminates; otherwise reenter the gadget directly. IF is
    ; forced on: the entry context is PASSIVE_LEVEL and must take
    ; interrupts in its (brief) window before CR8 goes back up.
    mov rcx, [g_AsmStopFlag]
    test rcx, rcx
    jz @@reenter
    cmp DWORD PTR [rcx], 0
    jne AsmTerminateSelf
@@reenter:
    lea rax, [g_AsmRoutine]
    mov rax, [rax]
    mov [rbx], rax
    movzx eax, WORD PTR [g_AsmNativeCs]
    mov [rbx+8], rax
    mov rax, [rbx+16]
    or rax, 200h
    mov [rbx+16], rax
    mov rax, [g_AsmEntryRsp]
    mov [rbx+24], rax
    movzx eax, WORD PTR [g_AsmNativeSs]
    mov [rbx+32], rax
    ; RCX is not part of the IRETQ frame: set the block explicitly.
    ; Then abandon the pushed registers and the interrupted context.
    mov rcx, [g_AsmBlock]
    lea rsp, [rbx]
    iretq
AsmNmiStub ENDP

; /*++
;
; Part 4: #GP stub, GP stop teardown, default thunks, #MC stub.
;
; #GP frame (error code present), RSP on entry points at the code:
;
;     [RSP+00h] ErrorCode
;     [RSP+08h] RIP      (must be the faulting LTR for the cycle)
;     [RSP+10h] CS
;     [RSP+18h] RFLAGS
;     [RSP+20h] RSP
;     [RSP+28h] SS
;
; Validation is deliberately narrow but build-proof: error code must be
; 0 (null-selector LTR). The fault RIP is recorded, not allow-listed:
; the exact LTR offset inside KiRestoreProcessorControlState moves
; between builds, while the window argument is airtight - at HIGH_LEVEL
; under the custom IDT the only faultable instruction in flight is that
; LTR, because LGDT/LIDT were given valid descriptors and the AND
; touched resident GDT memory.
;
; --*/

PUBLIC AsmGpStub
AsmGpStub PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbx
    mov rbx, rsp
    add rbx, 64                    ; RBX -> error code
    cmp QWORD PTR [rbx], 0
    jne @@fatal
    ; Stash the interrupted RSP: the gadget uses no stack between its
    ; entry and this fault, so the #GP frame's RSP is the entry RSP the
    ; NMI teardown reenters with. Single writer, constant value: store
    ; unconditionally. A repeat stash proves a direct reentry happened.
    mov rax, [rbx+32]
    cmp QWORD PTR [g_AsmEntryRsp], 0
    jne @@repeat
    mov [g_AsmEntryRsp], rax
    jmp @@records
@@repeat:
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@records
    mov rax, cr8
    mov rdx, [g_AsmBlock]
    DO_RECORD rcx, 10, 13, QWORD PTR [rbx+8], QWORD PTR [rbx+32], rax, rdx
@@records:
    mov rax, cr8
    ; Expected fault first, so the debugger can pair it with the NMI.
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@norec1
    DO_RECORD rcx, 6, 13, QWORD PTR [rbx+8], QWORD PTR [rbx+32], rax, 0
@@norec1:
    ; Marker record: detail is the Committed address of the active
    ; mode, the lower bound the NMI handler will test against.
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@norec2
    cmp DWORD PTR [g_AsmApicMode], 1
    je @@markx2
    lea r10, [AsmApicXapicCommitted]
    jmp @@mark
@@markx2:
    lea r10, [AsmApicX2apicCommitted]
@@mark:
    mov rax, cr8
    DO_RECORD rcx, 7, 13, QWORD PTR [rbx+8], QWORD PTR [rbx+32], rax, r10
@@norec2:
    ; Enter the resend window. The #GP frame stays beneath: the stop
    ; path terminates from it. RBX survives the loops (they use RAX/RCX
    ; only, and the entry RSP is already stashed above).
    cmp DWORD PTR [g_AsmApicMode], 1
    je AsmApicWriteX2apic
    jmp AsmApicWriteXapic
@@fatal:
    ; A #GP with a nonzero code is never the null LTR: bugcheck with
    ; the fault context. Layout here is [err][RIP]... at RBX.
    mov rax, cr8
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@bug
    DO_RECORD rcx, 12, 13, QWORD PTR [rbx+8], QWORD PTR [rbx+32], rax, QWORD PTR [rbx]
@@bug:
    mov r11, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 28h
    mov ecx, 0E2h
    mov edx, 13
    mov r8, [rbx+8]
    mov r9, [rbx]
    mov QWORD PTR [rsp+20h], 0
    call KeBugCheckEx
    int 3
AsmGpStub ENDP

; AsmGpTeardownStop: entered by JMP from the APIC_WRITE loops when the
; stop flag is set. Same stack contract as the GP stub tail (pushes
; still on the stack; RBX already served its purpose and is abandoned).
; Restores the natives and terminates; the #GP frame beneath is simply
; discarded with everything else.

PUBLIC AsmGpTeardownStop
AsmGpTeardownStop PROC
    call AsmRestoreNatives         ; clobbers RAX only; RBX still frames
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@norec
    mov rax, cr8
    DO_RECORD rcx, 9, 13, QWORD PTR [rbx+8], QWORD PTR [rbx+32], rax, QWORD PTR [g_AsmNativeIdtrBase]
@@norec:
    jmp AsmTerminateSelf
AsmGpTeardownStop ENDP

; /*++
;
; Default thunks: one tiny entry per vector so the fatal path knows the
; exact vector. Every thunk normalizes the stack to
; [vector][error][RIP][CS][RFLAGS][RSP][SS] and jumps to the common
; handler. Error-code vectors keep the CPU-pushed code; the rest store
; a zero placeholder.
;
; Fixed stride, no address table: both shapes are padded to exactly 24
; bytes (err: 4+7+5 code plus 8 single-byte NOPs; no-err: 4+8+7+5), so
; AsmDefaultThunkAddress computes base + vector * 24. The DWORD stores
; keep every immediate 32 bits wide regardless of value, which is what
; makes the stride value-independent. The IDT builder looks each thunk
; up through that function.
;
; --*/

PUBLIC AsmDefaultThunkBase
AsmDefaultThunkBase LABEL BYTE

VecIdx = 0
REPT 256
  IF (VecIdx EQ 8) OR (VecIdx EQ 10) OR (VecIdx EQ 11) OR (VecIdx EQ 12) OR (VecIdx EQ 13) OR (VecIdx EQ 14) OR (VecIdx EQ 17) OR (VecIdx EQ 21) OR (VecIdx EQ 29) OR (VecIdx EQ 30)
    sub rsp, 8
    mov DWORD PTR [rsp], VecIdx
    jmp AsmDefaultCommon
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
  ELSE
    sub rsp, 16
    mov DWORD PTR [rsp+8], 0
    mov DWORD PTR [rsp], VecIdx
    jmp AsmDefaultCommon
  ENDIF
  VecIdx = VecIdx + 1
ENDM

PUBLIC AsmDefaultThunkAddress
AsmDefaultThunkAddress PROC        ; RCX = vector 0..255
    mov eax, ecx
    imul eax, eax, 24
    lea rdx, [AsmDefaultThunkBase]
    add rax, rdx
    ret
AsmDefaultThunkAddress ENDP

; AsmDefaultCommon: fatal path for every unexpected vector. Records,
; then KeBugCheckEx(MANUALLY_INITIATED_CRASH, vector, RIP, err, 0).
; The code is dying by design here; the record is best effort.

PUBLIC AsmDefaultCommon
AsmDefaultCommon PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbx
    mov rbx, rsp
    add rbx, 64                    ; RBX -> [vector][error][RIP]...
    mov rax, cr8
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@bug
    DO_RECORD rcx, 12, DWORD PTR [rbx], QWORD PTR [rbx+16], QWORD PTR [rbx+40], rax, QWORD PTR [rbx+8]
@@bug:
    mov r11, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 28h
    mov ecx, 0E2h
    mov edx, DWORD PTR [rbx]
    mov r8, [rbx+16]
    mov r9, [rbx+8]
    mov QWORD PTR [rsp+20h], 0
    call KeBugCheckEx
    int 3
AsmDefaultCommon ENDP

; AsmMcStub: vector 18 has no error code. A machine check under the
; experiment cannot be continued past: record and bugcheck with the
; architectural MACHINE_CHECK_EXCEPTION code.

PUBLIC AsmMcStub
AsmMcStub PROC
    push rax
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    push rbx
    mov rbx, rsp
    add rbx, 64                    ; RBX -> NMI-shaped frame (RIP)
    mov rax, cr8
    mov rcx, [g_AsmEventBuffer]
    test rcx, rcx
    jz @@bug
    DO_RECORD rcx, 12, 18, QWORD PTR [rbx], QWORD PTR [rbx+24], rax, 0
@@bug:
    mov r11, rsp
    and rsp, 0FFFFFFFFFFFFFFF0h
    sub rsp, 28h
    mov ecx, 9Ch
    mov rdx, [rbx]
    mov r8, 0
    mov r9, 0
    mov QWORD PTR [rsp+20h], 0
    call KeBugCheckEx
    int 3
AsmMcStub ENDP

END
