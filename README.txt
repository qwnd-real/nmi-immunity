================================================================================
nmi-abuse -- an NMI-atomic code section inside KiRestoreProcessorControlState
================================================================================

Status:    research driver (x64 Windows kernel, WDM, no KMDF)
Platform:  x86-64 Windows kernel
Interface: none (no device object, no IOCTL; primitive service driver)
License:   MIT

What this is
------------

nmi-abuse creates a code section in which no NMI can observably interrupt
the experiment, while every genuine NMI still reaches Windows afterwards,
delivered in Windows context once the section is done -- and it does so
with a thread whose instruction pointer, whenever the scheduler could
ever preempt it, resides inside ntoskrnl.exe and nowhere else.

Concretely: the driver borrows the first instructions of the kernel's own
KiRestoreProcessorControlState as a trampoline. Each cycle loads a crafted
processor-state block (custom IDT, faulting TR, masked TPR), takes an
expected fault into a window that issues a self-NMI, consumes exactly one
NMI delivery, restores the native descriptor tables, and reenters the same
kernel bytes. A foreign NMI that lands mid-cycle is answered with exactly
one compensating self-NMI, so Windows still fires its own NMI handling
afterwards. The experiment thread is born inside the gadget and reenters
it directly on every cycle; it never executes driver code as a
preemptible thread.

  WARNING: kernel research for machines their operator owns and is
  authorized to test. This loads a test-signed driver, pins a CPU that
  it then hogs ~99%+, masks that CPU's maskable interrupts in long
  stretches, and deliberately vectors NMIs and faults through custom
  tables. A bug anywhere on the custom-IDT paths is a bugcheck, by
  design (unexpected vectors bugcheck rather than guess). Read the
  disclaimer at the end before running anything.

How to read this file
---------------------

Sections follow the cycle in order: the gadget, the register block, the
thread's birth, the descriptor trick, the custom IDT, the APIC window,
the NMI handler (all three paths), reentry, stop/unload, observability,
layout, building, and machine notes. Notation: TPR = the 4-bit task
priority in CR8 (0..15). IRQL names (PASSIVE_LEVEL, HIGH_LEVEL=31) are
the kernel's numbering, which is NOT what CR8 holds -- see below.

1. The gadget
-------------

ntoskrnl.exe exports no symbol for it, so the driver finds
KiRestoreProcessorControlState by signature: resolved once at load from
the loaded-module list (ZwQuerySystemInformation, SystemModuleInformation)
by KmModule, which parses the in-memory PE headers and scans resident,
readable, executable, non-discardable, non-PAGE/INIT sections. The
pattern is the routine's opening, and it must match exactly once:

    48 8B 01       mov rax, [rcx]
    0F 22 C0       mov cr0, rax
    48 8B 41 10    mov rax, [rcx+10h]
    0F 22 D8       mov cr3, rax

A match is a candidate address, nothing more. The full prefix the cycle
rides (from the reference disassembly) is:

    mov rax, [rcx]              ; Cr0
    mov cr0, rax
    mov rax, [rcx+10h]          ; Cr3
    mov cr3, rax
    mov rax, [rcx+18h]          ; Cr4
    mov cr4, rax
    mov rax, [rcx+0A0h]         ; TPR
    mov cr8, rax
    ...VSL/HyperV branch...     ; assumed never taken (section 9)
    lgdt  fword ptr [rcx+56h]
    lidt  fword ptr [rcx+66h]
    movzx eax, word ptr [rcx+70h] ; Tr
    add   rax, [rcx+58h]          ; GdtBase + Tr
    and   byte ptr [rax+5], 0FDh  ; clear TSS busy bit
    ltr   word ptr [rcx+70h]      ; <-- faults by design (section 4)
    mov   ax, [rcx+72h]
    lldt  ax

Two load-bearing properties fall out of this listing. First, the gadget
uses no stack between its entry and the faulting LTR (no push/call/sub),
so the fault frame's RSP *is* the entry RSP -- the reentry protocol
(section 7) rests on this. Second, everything before the LTR is either a
same-value control-register rewrite or a same-content table reload, so a
cycle is side-effect free right up to the fault.

2. The register block (RCX)
---------------------------

RCX points at a crafted KSPECIAL_REGISTERS (Tables.h, byte-identical to
the kernel layout). Only the fields the gadget reads before the fault
matter; the rest is carried so a debugger dump of RCX reads coherently:

    offset  field   content
    ------  -----   -------
    +0x00   Cr0     live __readcr0()  (rewritten identically)
    +0x10   Cr3     live __readcr3()  (System address space, pinned CPU)
    +0x18   Cr4     live __readcr4()
    +0x50   Gdtr    NATIVE Gdtr, verbatim (section 4)
    +0x60   Idtr    custom IDT (section 5)
    +0x70   Tr      0x0000 -- the faulting null selector (section 4)
    +0xA0   Cr8     15 (TPR, see below)

The Cr8 value is the one place the naive reading of the task ("Cr8 MUST
be HIGH_LEVEL") would crash the machine, so it is stated explicitly:
CR8 implements bits 3:0 only, and loading any value with bits 63:4 set
raises #GP -- and HIGH_LEVEL as an IRQL constant is 31 (0x1F). A
`mov cr8, 31` inside the gadget would fault while the *native* IDT is
still loaded. The block therefore carries TABLES_CR8_BLOCK_ALL = 15,
the highest representable TPR, which masks every maskable vector --
the entire intent, with no fault. The kernel's own save path stores
__readcr8(), likewise a 0..15 TPR value, so 15 is also what a real
"fully masked" block would contain.

3. Birth: a thread that lives in ntoskrnl
-----------------------------------------

There is no wrapper routine. WorkerStart (Worker.cpp, PASSIVE_LEVEL,
running on the loading thread pinned to the target CPU) prepares
everything, then:

    PsCreateSystemThread(&h, ..., StartRoutine = (PKSTART_ROUTINE)Routine,
                         StartContext = Block);

x64 thread startup calls StartRoutine(StartContext), so the first
argument register already holds the block when the gadget's first
instruction retires. The thread's birth RIP is a kernel address; no
driver frame is ever beneath it (PspSystemThreadStartup's call frame
is, but it is never returned to -- the cycle abandons and reenters
above it forever, until the self-termination in section 8).

Pinning: the setup captures the executing CPU, so it runs pinned there
(KeSetSystemGroupAffinityThread); the newborn is pinned to the same CPU
with ZwSetInformationThread(ThreadAffinityMask), and the mask is read
back with ZwQueryInformationThread and compared -- an unpinned thread
fails load loudly instead of cycling on the wrong CPU. Pinning is
currently group-0-only (the legacy mask cannot name another group);
a first processor outside group 0 fails load with a message.

Proof: the gadget is a straight line to the faulting LTR, so a healthy
thread reaches the #GP stub within milliseconds. Start polls the stub's
entry-RSP stash (g_AsmEntryRsp) for up to 30 s; nonzero means the thread
faulted as designed and entered the window -- the experiment is cycling.
On timeout the stop is set, the thread gets a bounded wait, and if it
somehow still lives its tables are deliberately leaked rather than
freed from underneath a thread that may still vector through them.

4. The descriptor trick: Windows' GDT, a null TR
------------------------------------------------

There is no private GDT. The block reuses the native GDTR verbatim, so
the gadget's LGDT reloads the Windows GDT that is already valid on the
pinned CPU. Only the IDT is custom, and only TR is crafted -- and the
craft is a single zero:

    Tr = 0x0000.

With Tr = 0 the gadget's busy-bit sequence becomes:

    movzx eax, word [rcx+70h]   ; eax = 0
    add   rax, [rcx+58h]        ; rax = GdtBase
    and   byte [rax+5], 0FDh    ; null descriptor byte 5 &= ~2 = no-op
    ltr   0                     ; #GP(0), deterministically

The null descriptor is all zeros, so the AND touches writable, resident
GDT memory and changes nothing; the LTR then faults because a null
selector can never be loaded into TR. Error code 0, vector 13 -- the
expected fault. The previously loaded (native) TSS stays active
throughout, because the faulting LTR never completes; its IST
configuration therefore still matters, which is why every custom gate
uses IST index 0 and all handling stays on the thread stack (that is
what makes the frame surgery in sections 6-7 possible at all).

Native TR is intentionally never captured (no MSVC intrinsic reads STR,
and none is needed): nothing on either path ever reloads TR, so there
is nothing to restore. GDTR itself is read with a 3-line MASM helper
(AsmReadGdtr: `sgdt fword ptr [rcx]`), because this toolchain exposes
no _sgdt intrinsic; CS/SS come from RtlCaptureContext for the same
toolchain reason.

5. The custom IDT
-----------------

One page, 256 sixteen-byte gates, built fatal-first: every gate starts
as a thunk that records its exact vector and bugchecks
(MANUALLY_INITIATED_CRASH with vector/RIP/error), and three vectors get
real handlers. Gate format throughout: present, DPL 0, type 0xE
(interrupt gate), selector = the native kernel code selector captured
at setup, IST 0.

    vector  entry                     error code?
    ------  -----                     ------------
    2       AsmNmiStub                no   (section 6)
    13      AsmGpStub                 yes  (expected: code 0, section 6)
    18      AsmMcStub                 no   (record + MACHINE_CHECK_EXCEPTION)
    other   per-vector thunk          normalized (fatal)

The thunks exist so an unexpected delivery always names its vector
before dying: error-code vectors keep the CPU-pushed code, the rest get
a zero placeholder, normalizing every frame to
[vector][error][RIP][CS][RFLAGS][RSP][SS] before a shared common
handler. Both shapes are padded to a fixed 24-byte stride (DWORD
stores keep every immediate 32 bits wide regardless of value), so the
builder computes thunk addresses as base + vector*24 with no table.

#MC is given a real (fatal) gate rather than left to the thunks
because a machine check remains possible at TPR 15 and deserves its
architectural bugcheck code rather than the generic one. Anything else
under the custom IDT means the experiment, not Windows, is at fault --
hence bugcheck, never guess.

6. The APIC window and the NMI handler
--------------------------------------

Mode detection runs once at setup (Apic.cpp): CPUID.1 ECX[21] for x2APIC
support plus the ENABLE_X2APIC bit in IA32_APIC_BASE. x2APIC mode needs
nothing mapped; xAPIC mode maps the 4K register page non-cached for the
ICR pair. The request itself -- one self-NMI, vector 0, NMI delivery
mode, self shorthand (ICR low 0x40400, high 0) -- lives in assembly, so
a marker can sit exactly after the write:

    xAPIC:  mov [ICR_high], 0
            mov [ICR_low], 0x40400
    Committed:                      <-- marker: the write completed
            pause x 100000
            stop check (once per batch)
            jmp ICR write
    End:                            <-- interval end (pure marker)

    x2APIC: mov ecx, 0x830; xor edx, edx; mov eax, 0x40400; wrmsr
            (same shape around it)

The NMI stub reads the interrupted RIP from its own trap frame and
compares it against [Committed, End) of the active mode. Three paths:

  * Transparent -- no entry RSP stashed yet. The #GP stub has not run,
    so this NMI landed in the first instructions of the first cycle and
    no request of ours could have completed: it is foreign. One
    compensating ICR write, then IRETQ back to the interrupted context
    unchanged. Execution continues into the #GP stub; the compensation
    arrives later via the native IDT.

  * Expected -- RIP inside the window. The delivery is consumed as our
    own request. No reissue. Teardown and reentry (section 7).

  * Foreign -- RIP outside the window with the protocol up. The delivery
    cannot be our request, so it is foreign and now consumed. Exactly
    one compensating ICR write keeps Windows whole, then teardown.

The honest table -- what each delivery costs Windows:

    delivery                    Windows receives
    --------                    ----------------
    self-NMI, no foreign near   nothing (consumed; it was ours)
    foreign before our write    our later self-NMI (transparent path) +
                                the compensation: whole
    foreign inside our window   possibly nothing -- see below
    stop requested              the terminating thread is gone; any
                                latched request still arrives natively

  The coalescing bound (deliberate, documented, not fixable): "NMI
  pending" is one architectural latch, not a count. A foreign NMI
  raised between our ICR write and its delivery merges with ours into a
  single delivery, which the RIP test consumes as expected. If no second
  request stayed latched, the foreign event never reaches Windows. The
  RIP window identifies interrupted *code*, and no observation available
  inside the handler identifies the *source* -- an NMI carries none.
  What this buys is a bounded reinjection rate (the window is a few
  instruction boundaries wide; the loss case needs a foreign NMI inside
  exactly it), not a guarantee. Experiments requiring exact foreign-NMI
  accounting cannot use this scheme.

7. Reentry: abandon, never resume
---------------------------------

The teardown restores the natives first -- LIDT/LGDT native, then CR8 0
(order matters: pending interrupts must find the native IDT the moment
they unmask) -- records, counts the cycle, then patches its *own* NMI
frame into a reentry frame and executes IRETQ, which also unblocks
further NMIs:

    [frame RIP]    = gadget address  (g_AsmRoutine)
    [frame CS/SS]  = native selectors
    [frame RFLAGS] = interrupted RFLAGS with IF forced on
    [frame RSP]    = stashed entry RSP (g_AsmEntryRsp)
    RCX            = block           (IRETQ does not restore RCX)

The interrupted context (pause loop, fault frame, stub pushes) is
abandoned by switching RSP -- frames never accumulate. The entry RSP is
valid forever because the gadget uses no stack before the fault, and it
is stashed by the single-writer #GP stub on its way into the window
(a repeat stash additionally records ReentryPrepared, proving a direct
reentry happened). RCX is reset to the block by construction on every
entry, satisfying the protocol's core invariant without any C++ loop:
the thread never leaves the gadget except to die.

8. Stop, unload, and what the debugger shows
--------------------------------------------

WorkerStop sets the flag. The thread observes it on its current cycle --
at the next NMI teardown, or inside the next APIC_WRITE batch, whose
stop check terminates from the #GP frame. Both stop paths restore the
natives, record StopRequested, and call PsTerminateSystemThread on the
clean entry stack (native IDT, CR8 passive: an ordinary call again).
WorkerStop waits on the thread object without a timeout -- the thread is
guaranteed one cycle out -- then dumps the event history, frees the IDT
and block, unmaps the xAPIC window, and releases the thread objects.
Freeing before the wait would pull the IDT out from under a live
handler; the wait is what makes the teardown order safe.

Two output channels, strictly separated by execution context:

  * Debug.h (KmError/KmWarning/KmPrint/KmTrace over DbgPrintEx,
    DPFLTR_IHVDRIVER_ID, checked builds only): setup, teardown, lifecycle
    -- PASSIVE_LEVEL with native tables. Never called from the custom
    window.
  * Trace.h (KM_EVENT_BUFFER, 256 append-only numeric records, lock-free
    single-attempt reservation so a nested NMI producer can never wait):
    everything observed while the custom IDT is loaded -- pin, capture,
    prepare, expected fault, post-write marker, NMI entry, restore,
    reentry, stop, unexpected fault. Dumped once, after the thread died,
    via KmEventDump. A full or contended buffer drops diagnostics and
    says so; dispatch never depends on recording.

9. Repository layout
--------------------

    nmi-abuse/  Apic.h/.cpp      xAPIC/x2APIC detection + xAPIC mapping
                Asm.h/Asm.asm    stubs, APIC_WRITE windows + markers,
                                 teardown/reentry/terminate, GDTR read
                Debug.h/.cpp     checked-build text emitter (PASSIVE only)
                Entry.h/.cpp     DriverEntry/DriverUnload wiring
                KmModule.h/.cpp  module list + executable-section scan
                Restore.h/.cpp   gadget signature discovery
                Tables.h/.cpp    native capture, custom IDT, RCX block
                Trace.h/.cpp     bounded event recorder + asm forwarder
                Worker.h/.cpp    pin, setup, direct birth, proof, stop
                nmi-abuse.inf    primitive service INF (no devices)
                nmi-abuse.vcxproj / .filters / .user

10. Building and running
------------------------

Toolchain: Visual Studio with the WDM toolset plus a matching WDK
(x64-only experiment; ARM64 configs compile to a loader that refuses
with STATUS_NOT_SUPPORTED). Full matrix, zero warnings, PREfast clean:

    msbuild nmi-abuse\nmi-abuse.vcxproj -p:Configuration=Debug   -p:Platform=x64
    msbuild nmi-abuse\nmi-abuse.vcxproj -p:Configuration=Release -p:Platform=x64

If package verification fails on a missing InfVerif.dll, that is a
broken WDK install on the build machine (it fails the same way for any
driver there); pass -p:SkipPackageVerification=true for local iteration
only -- do not bake it into the project. Loading needs test signing on
the target; the INF installs a demand-start kernel service and nothing
else (primitive driver: right-click Install, or pnputil, then
`sc start nmi-abuse`; `sc stop nmi-abuse` to end).

Machine notes: the VSL/HyperV branch inside the gadget is assumed never
taken -- discovery finds bytes, it cannot check runtime flags, so VBS /
Hyper-V-root hosts are out of scope. The pinned CPU is hogged but not
hung: pending work drains in every cycle's passive windows, and
preemption in the entry sliver only delays. Group-0-only
pinning; first processor elsewhere fails load.

Disclaimer
----------

Research into how Windows behaves when its own processor-restore path is
made to host an NMI-atomic section -- on hardware its operator owns, for
research. Not a product, not stealth tooling: the thread spins a CPU at
TPR 15 while loaded, and any bug on the custom-IDT paths is a bugcheck.
Do not run it on systems you do not own or are not authorized to test.

License
-------

Released under the MIT license.
