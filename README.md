# nmi-abuse

[![status: research driver](https://img.shields.io/badge/status-research%20driver-red)](#disclaimer)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](#license)
[![platform: x64 Windows kernel](https://img.shields.io/badge/platform-x86__64%20Windows%20kernel-blue)](#building)
[![driver: WDM](https://img.shields.io/badge/driver-WDM%20%28no%20KMDF%29-lightgrey)](#repository-layout)
[![language: C++ and MASM](https://img.shields.io/badge/language-C%2B%2B%20%2B%20MASM-orange)](#repository-layout)
[![interface: none](https://img.shields.io/badge/interface-none%20%28primitive%20service%29-informational)](#building)

**nmi-abuse** is a kernel research driver that builds a code section in
which no NMI can observably interrupt the experiment, while every genuine
NMI still reaches Windows afterwards — fired in Windows context once the
section is done. It does this with a thread whose instruction pointer,
whenever the scheduler could ever preempt it, resides inside ntoskrnl.exe
and nowhere else: the thread is born inside `KiRestoreProcessorControlState`
with a crafted processor-state block in RCX, faults into a custom IDT by
design, issues a self-NMI, consumes exactly one delivery, restores the
native tables, and reenters the same kernel bytes. Directly. Forever, until
told to stop — at which point it restores everything and terminates itself.

> [!WARNING]
> Kernel research for machines their operator owns and is authorized to
> test. This loads a test-signed driver, pins a CPU that it then hogs
> ~99%+, masks that CPU's maskable interrupts in long stretches, and
> deliberately vectors NMIs and faults through custom tables. A bug
> anywhere on the custom-IDT paths is a bugcheck, by design. Read the
> [disclaimer](#disclaimer) before running anything.

## The thesis

What the project achieves, precisely:

1. **An NMI-atomic section.** NMIs still physically arrive mid-cycle (they
   must — the self-NMI is the cycle's clock). The atomicity is
   observational: no handler ever *resumes* the interrupted experiment
   context, except the transparent early path, which changes nothing.
   Every cycle either completes into a teardown or never observably ran —
   frames are abandoned and reentered, never continued.
2. **Windows-context redelivery.** A foreign NMI consumed mid-cycle is
   answered with exactly one compensating self-NMI, so Windows still fires
   its own NMI handling (HAL callbacks / bugcheck path) afterwards —
   delayed by microseconds, delivered in Windows context, through the
   native IDT.
3. **A thread that lives in ntoskrnl.** Preemption is only possible where
   RIP is already kernel bytes: handlers run in trap context (the
   scheduler cannot preempt NMI/#GP context — DPCs can't retire into it),
   the pause loop runs at TPR 15 (DPCs masked). Driver `.text` executes
   transiently in trap context or setup, never as a preemptible thread.

Notation: TPR = the 4-bit task priority in CR8 (0..15). IRQL names
(`PASSIVE_LEVEL`, `HIGH_LEVEL` = 15 on x64) are the kernel's numbering.

## The gadget

ntoskrnl.exe exports no symbol for it, so the driver finds
`KiRestoreProcessorControlState` by signature: resolved once at load from
the loaded-module list (`ZwQuerySystemInformation`,
`SystemModuleInformation`) by `KmModule`, which parses the in-memory PE
headers and scans resident, readable, executable, non-discardable,
non-PAGE/INIT sections. The pattern is the routine's opening, and it must
match exactly once:

```asm
48 8B 01       mov rax, [rcx]
0F 22 C0       mov cr0, rax
48 8B 41 10    mov rax, [rcx+10h]
0F 22 D8       mov cr3, rax
```

A match is a candidate address, nothing more. The full prefix the cycle
rides is:

```asm
mov rax, [rcx]                ; Cr0
mov cr0, rax
mov rax, [rcx+10h]            ; Cr3
mov cr3, rax
mov rax, [rcx+18h]            ; Cr4
mov cr4, rax
mov rax, [rcx+0A0h]           ; TPR
mov cr8, rax
...VSL/HyperV branch...       ; assumed never taken (see machine notes)
lgdt  fword ptr [rcx+56h]
lidt  fword ptr [rcx+66h]
movzx eax, word ptr [rcx+70h] ; Tr
add   rax, [rcx+58h]          ; GdtBase + Tr
and   byte ptr [rax+5], 0FDh  ; clear TSS busy bit
ltr   word ptr [rcx+70h]      ; <-- faults by design
mov   ax, [rcx+72h]
lldt  ax
```

Two load-bearing properties fall out of this listing. First, the gadget
uses **no stack** between its entry and the faulting `LTR` (no
push/call/sub), so the fault frame's RSP *is* the entry RSP — the reentry
protocol rests on this. Second, everything before the `LTR` is either a
same-value control-register rewrite or a same-content table reload, so a
cycle is side-effect free right up to the fault.

## The register block (RCX)

RCX points at a crafted `KSPECIAL_REGISTERS` (`Tables.h`, byte-identical
to the kernel layout). Only the fields the gadget reads before the fault
matter; the rest is carried so a debugger dump of RCX reads coherently.

| Offset | Field | Content |
| --- | --- | --- |
| `+0x00` | Cr0 | live `__readcr0()` (rewritten identically) |
| `+0x10` | Cr3 | live `__readcr3()` (System space, pinned CPU) |
| `+0x18` | Cr4 | live `__readcr4()` |
| `+0x50` | Gdtr | **native** Gdtr, verbatim |
| `+0x60` | Idtr | custom IDT |
| `+0x70` | Tr | `0x0000` — the faulting null selector |
| `+0xA0` | Cr8 | `HIGH_LEVEL` (= 15 on x64 — see below) |

The Cr8 value works because of an x64 coincidence worth stating once:
`HIGH_LEVEL` is 15 here — the highest IRQL *and* the highest
representable TPR. CR8 implements bits 3:0 only, so the gadget's
`mov cr8, rax` is legal exactly because the value stays within 0..15,
and 15 masks every maskable vector, which is the entire intent. (On x86
`HIGH_LEVEL` is 31 and this block would not transfer as-is; the
experiment is x64-only.) The kernel's own save path stores
`__readcr8()`, likewise a 0..15 TPR value.

## Birth: a thread that lives in ntoskrnl

There is no wrapper routine. `WorkerStart` (`Worker.cpp`, `PASSIVE_LEVEL`,
running on the loading thread pinned to the target CPU) prepares
everything, then:

```c
PsCreateSystemThread(&h, ..., StartRoutine = (PKSTART_ROUTINE)Routine,
                     StartContext = Block);
```

x64 thread startup calls `StartRoutine(StartContext)`, so the first
argument register already holds the block when the gadget's first
instruction retires. The thread's birth RIP is a kernel address; no driver
frame is ever beneath it (startup's call frame is, but it is never
returned to — the cycle abandons and reenters above it forever, until the
self-termination below).

**Pinning.** The setup captures the executing CPU, so it runs pinned there
(`KeSetSystemGroupAffinityThread`); the newborn is pinned to the same CPU
with `ZwSetInformationThread(ThreadAffinityMask)`, whose status is the
validation (the kernel checks the mask; there is deliberately no
read-back — the query side doesn't implement the class). Pinning is
currently group-0-only (the legacy mask cannot name another group); a
first processor outside group 0 fails load with a message. Every failure
after creation stops the thread and waits for its exit *before* freeing
the IDT, block, or APIC window — freeing first would pull the tables out
from under a live handler.

**Proof.** The gadget is a straight line to the faulting `LTR`, so a
healthy thread reaches the #GP stub within milliseconds. Start polls the
stub's entry-RSP stash (`g_AsmEntryRsp`) for up to 30 s; nonzero means the
thread faulted as designed and entered the window — the experiment is
cycling. On timeout the stop is set, the thread gets a bounded wait, and
if it somehow still lives its tables are deliberately leaked rather than
freed from underneath a thread that may still vector through them.

## The descriptor trick: Windows' GDT, a null TR

There is no private GDT. The block reuses the native GDTR verbatim, so
the gadget's `LGDT` reloads the Windows GDT that is already valid on the
pinned CPU. Only the IDT is custom, and only TR is crafted — and the
craft is a single zero:

```c
Tr = 0x0000;
```

With `Tr = 0` the gadget's busy-bit sequence becomes:

```asm
movzx eax, word [rcx+70h]   ; eax = 0
add   rax, [rcx+58h]        ; rax = GdtBase
and   byte [rax+5], 0FDh    ; null descriptor byte 5 &= ~2 = no-op
ltr   0                     ; #GP(0), deterministically
```

The null descriptor is all zeros, so the `AND` touches writable, resident
GDT memory and changes nothing; the `LTR` then faults because a null
selector can never be loaded into TR. Error code 0, vector 13 — the
expected fault. The previously loaded (native) TSS stays active
throughout, because the faulting `LTR` never completes; its IST
configuration therefore still matters, which is why every custom gate
uses IST index 0 and all handling stays on the thread stack (that is what
makes the frame surgery below possible at all).

Native TR is intentionally never captured (no MSVC intrinsic reads STR,
and none is needed): nothing on either path ever reloads TR, so there is
nothing to restore. GDTR itself is read with a 3-line MASM helper
(`AsmReadGdtr`: `sgdt fword ptr [rcx]`), because this toolchain exposes
no `_sgdt` intrinsic; CS/SS come from `RtlCaptureContext` for the same
toolchain reason.

## The custom IDT

One page, 256 sixteen-byte gates, built fatal-first: every gate starts as
a thunk that records its exact vector and bugchecks
(`MANUALLY_INITIATED_CRASH` with vector/RIP/error), and three vectors get
real handlers. Gate format throughout: present, DPL 0, type `0xE`
(interrupt gate), selector = the native kernel code selector captured at
setup, IST 0.

| Vector | Entry | Error code? |
| --- | --- | --- |
| 2 | `AsmNmiStub` | no |
| 13 | `AsmGpStub` | yes — expected: code 0 |
| 18 | `AsmMcStub` | no — record + `MACHINE_CHECK_EXCEPTION` |
| other | per-vector thunk | normalized (fatal) |

The thunks exist so an unexpected delivery always names its vector before
dying: error-code vectors keep the CPU-pushed code, the rest get a zero
placeholder, normalizing every frame to
`[vector][error][RIP][CS][RFLAGS][RSP][SS]` before a shared common
handler. Both shapes are padded to a fixed 24-byte stride (`DWORD` stores
keep every immediate 32 bits wide regardless of value), so the builder
computes thunk addresses as base + vector\*24 with no table.

`#MC` gets a real (fatal) gate rather than a thunk because a machine
check remains possible at TPR 15 and deserves its architectural bugcheck
code. Anything else under the custom IDT means the experiment, not
Windows, is at fault — hence bugcheck, never guess.

## The APIC window and the NMI handler

Mode detection runs once at setup (`Apic.cpp`): CPUID.1 ECX[21] for x2APIC
support plus the `ENABLE_X2APIC` bit in `IA32_APIC_BASE`. x2APIC mode needs
nothing mapped; xAPIC mode maps the 4K register page non-cached for the
ICR pair. Setup also captures the pinned CPU's hardware APIC ID from
xAPIC register `+0x20` (bits 31:24) or x2APIC MSR `0x802` (all 32 bits).
Both loop and synthetic NMIs explicitly address that physical ID with
ICR low `0x400`: NMI delivery, edge trigger, no destination shorthand.
The Windows processor number is not used as an APIC ID.

AMD APM Volume 2, Table 16-4 excludes the **Self** destination shorthand
for NMI. The old `0x40400` combined individually valid fields into an
unsupported command; VM acceptance did not establish hardware support.
The assembly send macros share the corrected encoding and keep each
`Committed` marker immediately after the issuing write:

```asm
; xAPIC:
mov  edx, [g_AsmApicId]
shl  edx, 24
mov  [ICR_high], edx
mov  [ICR_low], 400h
Committed:                        ; <-- marker: the write completed
    mov  ecx, 20000
spin:
    pause
    dec  ecx
    jnz  spin
    ; stop check, once per batch
    jmp  issue
End:                              ; <-- interval end (pure marker)

; x2APIC: mov ecx, 830h / mov edx, [g_AsmApicId] / mov eax, 400h / wrmsr
;         (same shape around it)
```

The NMI stub reads the interrupted RIP from its own trap frame and
compares it against `[Committed, End)` of the active mode. The check is
diagnostic — behavior no longer diverges, by necessity (see note).
Three paths:

- **Transparent** — no entry RSP stashed yet. The #GP stub has not run, so
  this NMI landed in the first instructions of the first cycle and no
  request of ours could have completed: it is foreign. One synthetic
  self-NMI, then `IRETQ` back to the interrupted context unchanged (no
  restore — the custom IDT must stay loaded). The synthetic is consumed
  under the custom IDT as the prologue completes, so this path can never
  reach native.
- **Expected** — RIP inside the window. The delivery is consumed as our own
  request. Shared teardown and reentry.
- **Foreign** — RIP outside the window with the protocol up. Genuinely
  foreign: post-stash, no request of ours can be outstanding outside the
  loop, so this cannot be a misclassified self-NMI — on the target, an
  ICR-sent NMI from Windows or an anti-cheat, sourceless by construction
  exactly like our own. Recorded as the unexpected vector-2 delivery it
  is (the `NmiEntry` sibling carries the interrupted RIP for offline
  judging), then answered with exactly one synthetic self-NMI: the
  design's only allowed crosser. It is consumed natively right after the
  shared teardown's restore+`iretq` — it cannot age past the entry
  sliver, a latched NMI is recognized at the first post-`iretq`
  boundary while the IDT is still native — where the sender's expecting
  NMI callback claims it, timing intact to microseconds and
  indistinguishable from the original to any check the protocol could
  run. If nothing claims it, Windows answers with
  `NMI_HARDWARE_FAILURE`; that outcome proves an unclaimed foreign
  arrived and is the accepted cost of the reinjection requirement.

The honest table — what each delivery costs Windows:

| Delivery | Windows receives |
| --- | --- |
| self-NMI, nothing foreign near | nothing (consumed; it was ours) |
| foreign before our write | the synthetic, natively — claimed by the sender's callback, or bugcheck if unclaimed |
| foreign inside our window | nothing (coalesced; see below) |
| foreign in prologue/tail | the synthetic, natively — same claimed-or-crash contract |
| level-latched hardware source | its own redelivery, natively, on top of the above |
| stop requested | the terminating thread is gone; drains leave nothing pending |

> [!NOTE]
> The coalescing bound (deliberate, documented, not fixable): "NMI
> pending" is one architectural latch, not a count. A foreign NMI raised
> between our ICR write and its delivery merges with ours into a single
> delivery, which the RIP test consumes as expected. If no second request
> stayed latched, the foreign event never reaches Windows. The RIP window
> identifies interrupted *code*, and no observation available inside the
> handler identifies the *source* — an NMI carries none.
>
> And the hard rule underneath it: the only crosser the design allows is
> the deliberate synthetic answer to a consumed foreign. Loop issues
> never cross — issues happen only at the loop top, every delivery is
> consumed in a stub, and the stop paths drain rather than terminate
> over a pending request. A loop issue crossing instead, sourceless and
> unowned, is answered by Windows with `NMI_HARDWARE_FAILURE`; that is
> how the first field crash read postmortem (a genuine foreign took the
> then-unconditional compensate path), and the GP-stop drain exists so
> unload can never reproduce it.

## Reentry: abandon, never resume

The teardown restores the natives first — `LIDT`/`LGDT` native, then CR8 0
(order matters: pending interrupts must find the native IDT the moment
they unmask) — records, counts the cycle, then patches its *own* NMI frame
into a reentry frame and executes `IRETQ`, which also unblocks further
NMIs:

| Frame slot | Value |
| --- | --- |
| RIP | gadget address (`g_AsmRoutine`) |
| CS / SS | native selectors |
| RFLAGS | interrupted RFLAGS with IF forced on |
| RSP | stashed entry RSP (`g_AsmEntryRsp`) |
| RCX | block (set explicitly — `IRETQ` does not restore RCX) |

The interrupted context (pause loop, fault frame, stub pushes) is
abandoned by switching RSP — frames never accumulate. The entry RSP is
valid forever because the gadget uses no stack before the fault, and it is
stashed by the single-writer #GP stub on its way into the window (a repeat
stash additionally records `ReentryPrepared`, proving a direct reentry
happened). RCX is reset to the block by construction on every entry,
satisfying the protocol's core invariant without any C++ loop: the thread
never leaves the gadget except to die.

The whole cycle, at a glance:

```
thread birth (PspSystemThreadStartup)
  RCX = block, RIP = KiRestore... (ntoskrnl)
  │
  ▼
mov cr0/cr3/cr4 .............. same-value rewrites, PASSIVE, native IDT
mov cr8, 15 .................. mask everything (TPR)
lgdt native / lidt custom
and [GdtBase+5], ~2 .......... no-op on the null descriptor
ltr 0 ........................ #GP(0), expected
  │
  ▼
#GP stub: stash entry RSP ────▶ APIC_WRITE
  │                                │
  │                           ICR write (self-NMI)
  │                           Committed: ◀── marker
  │                                │ pause x100000, stop check, reissue
  │                                ▼
  │                           NMI arrives
  │                                │
  │               ┌────────────────┼────────────────┐
  │               ▼                ▼                ▼
  │          transparent       expected          foreign
  │          (no stash)       (in window)     (out of window)
  │          synthetic +      consume,        synthetic +
  │          iret to ctx      teardown        shared teardown
  │          (custom-                         (crosses natively,
  │           consumed)                        callback claims)
  │               │                │                │
  │               │                ▼                ▼
  │               │         restore natives, CR8 = 0
  │               │         iretq ──▶ RIP = gadget,
  │               │                   RCX = block, RSP = entry RSP
  │               │                   (stop: terminate instead)
  ▼               ▼
 (transparent path rejoins the #GP stub; the loop continues)
```

## Stop, unload, and what the debugger shows

`WorkerStop` sets the flag. The thread observes it on its current cycle —
at the next NMI teardown, or inside the next `APIC_WRITE` batch, whose
stop check terminates from the #GP frame. Both stop paths restore the
natives, record `StopRequested`, and call `PsTerminateSystemThread` on the
clean entry stack (native IDT, CR8 passive: an ordinary call again).
`WorkerStop` waits on the thread object without a timeout — the thread is
guaranteed one cycle out — then dumps the event history, frees the IDT and
block, unmaps the xAPIC window, and releases the thread objects. Freeing
before the wait would pull the IDT out from under a live handler; the wait
is what makes the teardown order safe.

Two output channels, strictly separated by execution context:

- **Text** (`Debug.h`: `KmError`/`KmWarning`/`KmPrint`/`KmTrace` over
  `DbgPrintEx`, `DPFLTR_IHVDRIVER_ID`, checked builds only): setup,
  teardown, lifecycle — `PASSIVE_LEVEL` with native tables. Never called
  from the custom window.
- **Recorder** (`Trace.h`: `KM_EVENT_BUFFER`, 256 append-only numeric
  records, lock-free single-attempt reservation so a nested NMI producer
  can never wait): everything observed while the custom IDT is loaded.
  Dumped once, after the thread died, via `KmEventDump`. A full or
  contended buffer drops diagnostics and says so; dispatch never depends
  on recording.

| Event | Detail |
| --- | --- |
| `WorkerPinned` | captured kernel CR3 |
| `NativeCaptured` | native-state snapshot address |
| `RestorePrepared` | prepared block address |
| `ExpectedFault` | exception error code (0) |
| `IcrPostWrite` | marker address of the active mode |
| `NmiEntry` | interrupted RCX |
| `NativeTablesRestored` | restored IDT base |
| `ReentryPrepared` | RCX restored by the return path |
| `StopRequested` | zero |
| `UnexpectedFault` | error code, or zero |

## Repository layout

| Path | What it is |
| --- | --- |
| `Apic.h` / `Apic.cpp` | xAPIC/x2APIC detection + xAPIC mapping |
| `Asm.h` / `Asm.asm` | stubs, `APIC_WRITE` windows + markers, teardown / reentry / terminate, GDTR read |
| `Debug.h` / `Debug.cpp` | checked-build text emitter (`PASSIVE_LEVEL` only) |
| `Entry.h` / `Entry.cpp` | `DriverEntry` / `DriverUnload` wiring |
| `KmModule.h` / `KmModule.cpp` | module list + executable-section scan |
| `Restore.h` / `Restore.cpp` | gadget signature discovery |
| `Tables.h` / `Tables.cpp` | native capture, custom IDT, RCX block |
| `Trace.h` / `Trace.cpp` | bounded event recorder + asm forwarder |
| `Worker.h` / `Worker.cpp` | pin, setup, direct birth, proof, stop |
| `nmi-abuse.inf` | primitive service INF (no devices) |
| `nmi-abuse.vcxproj` / `.filters` / `.user` | build |

## Building

Needs the WDK and a matching Visual Studio. The experiment is x64-only by
design (CR8, `LGDT`/`LIDT`, MSR interfaces, MASM); ARM64 configs compile
to a loader that refuses with `STATUS_NOT_SUPPORTED`.

```
msbuild nmi-abuse\nmi-abuse.vcxproj -p:Configuration=Debug   -p:Platform=x64
msbuild nmi-abuse\nmi-abuse.vcxproj -p:Configuration=Release -p:Platform=x64
```

Full matrix (Debug/Release × x64/ARM64) builds with zero warnings and is
PREfast-clean. If package verification fails on a missing `InfVerif.dll`,
that is a broken WDK install on the build machine (it fails the same way
for any driver there); pass `-p:SkipPackageVerification=true` for local
iteration only — never bake it into the project.

Loading needs test signing on the target. The INF installs a demand-start
kernel service and nothing else (primitive driver: right-click Install, or
`pnputil`, then `sc start nmi-abuse`; `sc stop nmi-abuse` to end, which
takes one cycle at most).

Machine notes: the VSL/HyperV branch inside the gadget is assumed never
taken — discovery finds bytes, it cannot check runtime flags, so VBS /
Hyper-V-root hosts are out of scope. The pinned CPU is hogged but not
hung: pending work drains in every cycle's passive windows, and
preemption in the entry sliver only delays. Group-0-only pinning; a first
processor elsewhere fails load.

## Disclaimer

Research into how Windows behaves when its own processor-restore path is
made to host an NMI-atomic section — on hardware its operator owns, for
research. Not a product, not stealth tooling: the thread spins a CPU at
TPR 15 while loaded, and any bug on the custom-IDT paths is a bugcheck.
Do not run it on systems you do not own or are not authorized to test.

## License

Released under the MIT license.

