# nmi-immunity

[![status: PoC](https://img.shields.io/badge/status-PoC-red)](#poc-disclaimer)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](#license)
[![platform: x64 Windows kernel](https://img.shields.io/badge/platform-x86__64%20Windows%20kernel-blue)](#building)
[![driver: WDM](https://img.shields.io/badge/driver-WDM%20%28no%20KMDF%29-lightgrey)](#repository-layout)
[![language: C++ and MASM](https://img.shields.io/badge/language-C%2B%2B%20%2B%20MASM-orange)](#repository-layout)
[![interface: none](https://img.shields.io/badge/interface-none%20%28primitive%20service%29-informational)](#building)

**nmi-immunity** is a kernel research driver that builds a code section in
which no NMI can observably interrupt the section, while every genuine
NMI still reaches Windows afterwards, fired in Windows context once the
section is done. It does this with a thread whose instruction pointer,
whenever the scheduler could ever preempt it, resides inside ntoskrnl.exe
and nowhere else: the thread is born inside `KiRestoreProcessorControlState`
with a crafted processor-state block in RCX, faults into a custom IDT by
design, issues a self-NMI, consumes exactly one delivery, restores the
native tables, and reenters the same kernel bytes. Directly. Forever, until
told to stop, at which point it restores everything and terminates itself.

> [!WARNING]
> Kernel research for machines their operator owns and is authorized to
> test. This loads a test-signed driver, pins a CPU that it then hogs
> at ~99%+, masks that CPU's maskable interrupts in long stretches, and
> deliberately vectors NMIs and faults through custom tables. A bug
> anywhere on the custom-IDT paths is a bugcheck, by design. Read the
> [PoC disclaimer](#poc-disclaimer) before running anything.

## PoC disclaimer

This is a proof of concept, not a reliable primitive. It demonstrates the
mechanism end to end, but trusting it beyond controlled test runs requires
work in at least the three areas below. Each one is load-bearing for
reliability, and each one is currently in its simplest possible form.

### 1. Foreign/self-NMI differentiation

An NMI carries no source token. When the handler runs, the architecture
tells it the interrupted RIP and nothing about who raised the delivery.
The current design therefore classifies by code position: the NMI stub
reads the interrupted RIP from its own trap frame and checks it against
the `[Committed, End)` marker interval of the active APIC mode, combined
with whether the entry RSP has been stashed yet (transparent path) and
whether the protocol is up at all. That heuristic is exact for code
position and silent about identity, and the gap between those two is
where every reliability problem in this design lives.

The hard limit is physical, not a bug: "NMI pending" is a single
architectural latch, not a count. A foreign NMI raised between our ICR
write and the CPU's acceptance of our request merges with the self-NMI
into one delivery, which the RIP test then consumes as our own. If no
second request stayed latched, the foreign event never reaches Windows.
There are two such single-bit stages in series (the LAPIC pending latch
plus the CPU pending-while-blocked latch), and the vulnerable window is
the full self-NMI delivery latency, so the loss rate is load-bearing
rather than rare. The honest table in the handler section states the
cost per delivery exactly, including this row.

What exists today to manage that limit:

- The armed window is kept short relative to the cycle period. Each cycle
  spends most of its time disarmed (the configurable dwell pause, default
  4100 pauses, runs before the first ICR write with the latch provably
  empty), so the loss probability tracks P = 1 - L/T where L is the armed
  window and T the cycle period. The operating point is tunable without a
  rebuild through `g_AsmDwellIters`.
- A consumed foreign is answered with exactly one synthetic self-NMI, the
  design's only allowed crosser, delivered natively right after the shared
  teardown's restore + `iretq`, where the original sender's expecting NMI
  callback can claim it with microsecond-scale timing intact. If nothing
  claims it, Windows answers `NMI_HARDWARE_FAILURE`. That is the
  claimed-or-crash contract: reinjection is attempted, never guaranteed.
- Run counters (`g_AsmCycleCount`, `g_AsmIssueSeq`, served count, uptime
  TSC, per-delivery metric records) exist so loss can be judged offline
  instead of trusted blindly. The PING response exposes them to user mode.

What reliable use would still require:

- A stated, measured loss bound per machine and per operating point, not
  just the P = 1 - L/T model. Delivery latency varies with silicon,
  frequency scaling, and SMM activity; the bound has to be calibrated
  from the metric TSC deltas on the target, then re-verified whenever the
  platform or the dwell changes.
- Narrowing the armed window further (marker placement, fewer instructions
  between commit and acceptance check, no reissues while a request may be
  in flight) and proving the placement against the actual assembly, not
  against a diagram of it.
- Coordination with whoever else raises NMIs on the box (HAL watchdog,
  performance tooling, anti-cheat): either quiesce foreign sources while
  armed, or give the consumer a loss-accounting channel it can act on
  (retry, fence, abort the run) instead of silent coalescing.
- Deciding, explicitly, which vandalism the threat model tolerates. No
  in-handler observation can distinguish a coalesced foreign from a clean
  self-NMI after the fact. Any consumer that needs exact foreign-NMI
  accounting needs a different scheme (for example, running only inside a
  dwell it never arms from), not a tighter version of this one.

### 2. The CPU pin must go

Today the whole design is pinned: setup pins itself to processor index 0
in group 0 (`KeSetSystemGroupAffinityThread`), captures that CPU's CR3,
GDTR, IDTR, and APIC ID, and the worker thread is pinned to the same CPU
before it can complete a cycle anywhere else. Pinning is what makes the
captured state valid for every cycle without refresh. The price is
total: one CPU is hogged at TPR 15 for the entire run, only group 0 is
supported (a first processor in any other group fails load), and anything
that moves CPUs (hotplug, hibernate, scheduler or affinity games from
other software, virtualization that rebalances vCPUs) is outside the
design envelope.

Unpinning is not a matter of deleting the affinity calls. Everything the
pin currently guarantees has to be re-established per cycle or per CPU:

- Descriptor and control state (CR3, GDTR, IDTR, CS/SS, APIC ID and mode)
  would have to be captured per CPU at setup and selected by the CPU the
  thread actually runs on, or captured fresh on every entry. The block the
  gadget consumes in RCX is per-CPU data the moment the thread can
  migrate.
- The "RIP is always ntoskrnl bytes" invariant, which is what makes
  preemption safe today, must survive migration: either migration points
  stay inside the gadget prefix (benign on any CPU, same-content
  rewrites only), or each CPU gets a fully prepared cycle context before
  the thread may land there.
- Duty-cycle control becomes mandatory rather than polite. A pinned,
  hogged CPU is a test artifact; an unpinned design that still spends
  ~99% of one CPU at TPR 15 is a denial of service with extra steps.
  Preemptible sleeps between cycles, a bounded cycles-per-second budget,
  and scheduler-visible yielding all belong in the reliable version.
- Lifecycle must handle CPUs appearing and disappearing: re-capture on
  hotplug, drain before hibernate, never free per-CPU tables while a
  migrated thread may still vector through them.

Until that work is done, treat single-pinned-CPU hogging as a property
of the PoC, not a tunable: plan short test runs on a machine with CPUs
to spare, and expect clock, DPC, and scheduling latency artifacts on the
pinned CPU's neighbors under load.

### 3. The shared-memory transport must be reworked

Today the kernel/user channel is a registry dead-drop plus a locked
user buffer. Concretely: the consumer allocates exactly 8192 bytes,
writes one `SHM_HANDSHAKE` blob (magic, nonce, PID, user VA, size) as
`REG_BINARY` to `HKLM\SOFTWARE\MmDiag\Rendezvous`, then starts the
service. `DriverEntry` consumes the blob exactly once (validates magic,
size, address range, and PID, attaches to the process, MDL-locks the
buffer with a user-mode probe, maps it into system space, answers
`Status = OK` through the mapping itself), deletes the registry value,
and only then creates the worker. Requests after that are single-flight
`PING` / `READ_PHYS` / `WRITE_PHYS` (payloads capped at 4096 bytes) with
a `Pending` flag the consumer sets last and the NMI handler clears last.

That works for a bring-up demo and is wrong for anything else:

- The registry is a rendezvous hack, not a channel. It requires admin
  HKLM writes, carries no versioning or capability negotiation, supports
  exactly one consumer by construction, and leaves a stale blob behind
  on every failed load (the consumer has to clean it up on retry).
  A reload without a fresh writer fails the handshake by design, which
  is correct behavior for a dead-drop and an absurd one for a driver
  interface.
- Completion is polling. The consumer spins on `Pending` (20 s timeout
  for the handshake answer, 5 s per request) and the kernel side has no
  way to wake it. Every request pays polling latency and a polling CPU,
  and a wedged channel is indistinguishable from a slow one until the
  timeout fires.
- There is no access control beyond "can write HKLM and start services",
  no multi-client story, no request queue, and teardown ordering is pure
  convention: the consumer must stop submitting before unload, because a
  request in flight across `WorkerStop` is a bugcheck, and nothing in
  the protocol enforces the order.
- Error reporting across the channel is one status word with no
  diagnostics, no sequence integrity beyond an opaque echo, and no
  channel-health signal distinct from request results.

A reliable transport keeps the data plane (locked shared pages, bounded
NMI-side work, snapshot-then-validate) and replaces everything around
it: a real device interface (device object plus IOCTLs, or a
section-backed mapping with event-based completion), a handshake with
versions and capabilities, completion signaling instead of polling,
per-client state with an explicit close/drain path, an ACL that says who
may talk to the driver, and an unload protocol that revokes the channel
before anything the NMI side touches goes away. None of that exists
here, by design of the PoC scope.

### Other known limits (not roadmapped, just true)

- The VSL/Hyper-V branch inside the gadget is assumed never taken.
  Discovery finds bytes; it cannot check runtime flags. VBS and
  Hyper-V-rooted hosts are out of scope.
- Test signing is required on the target, and HVCI / memory-integrity
  policies may refuse the driver or the test certificate outright.
- Group-0-only pinning: a machine whose first processor is outside
  group 0 fails load.
- The pinned CPU is hogged, not hung: pending interrupts latch and drain
  in each cycle's passive windows, but plan test runs accordingly and
  keep the run short.

## The thesis

What the project achieves, precisely:

1. **An NMI-atomic section.** NMIs still physically arrive mid-cycle (they
   must: the self-NMI is the cycle's clock). The atomicity is
   observational: no handler ever *resumes* the interrupted section
   context, except the transparent early path, which changes nothing.
   Every cycle either completes into a teardown or never observably ran:
   frames are abandoned and reentered, never continued.
2. **Windows-context redelivery.** A foreign NMI consumed mid-cycle is
   answered with exactly one compensating self-NMI, so Windows still fires
   its own NMI handling (HAL callbacks / bugcheck path) afterwards,
   delayed by microseconds, delivered in Windows context, through the
   native IDT. Best effort, under the [coalescing bound](#poc-disclaimer):
   a foreign that merges into our own delivery has no second delivery to
   redeliver.
3. **A thread that lives in ntoskrnl.** Preemption is only possible where
   RIP is already kernel bytes: handlers run in trap context (the
   scheduler cannot preempt NMI/#GP context, and DPCs cannot retire into
   it), the pause loop runs at TPR 15 (DPCs masked). Driver `.text`
   executes transiently in trap context or setup, never as a preemptible
   thread.

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
push/call/sub), so the fault frame's RSP *is* the entry RSP: the reentry
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
| `+0x70` | Tr | `0x0000`, the faulting null selector |
| `+0xA0` | Cr8 | `HIGH_LEVEL` (= 15 on x64, see below) |

The Cr8 value works because of an x64 coincidence worth stating once:
`HIGH_LEVEL` is 15 here, the highest IRQL *and* the highest
representable TPR. CR8 implements bits 3:0 only, so the gadget's
`mov cr8, rax` is legal exactly because the value stays within 0..15,
and 15 masks every maskable vector, which is the entire intent. (On x86
`HIGH_LEVEL` is 31 and this block would not transfer as-is; the project
is x64-only.) The kernel's own save path stores
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
returned to: the cycle abandons and reenters above it forever, until the
self-termination below).

**Pinning.** The setup captures the executing CPU, so it runs pinned there
(`KeSetSystemGroupAffinityThread`); the newborn is pinned to the same CPU
with `ZwSetInformationThread(ThreadAffinityMask)`, whose status is the
validation (the kernel checks the mask; there is deliberately no
read-back: the query side does not implement the class). Pinning is
currently group-0-only (the legacy mask cannot name another group); a
first processor outside group 0 fails load with a message. Every failure
after creation stops the thread and waits for its exit *before* freeing
the IDT, block, or APIC window: freeing first would pull the tables out
from under a live handler. Removing the pin is [required work](#poc-disclaimer),
not a tuning option.

**No first-cycle proof.** Start returns as soon as the thread is born and
pinned; cycling is not awaited. A healthy thread stashes entry-RSP and
enters the window within milliseconds: watch `g_AsmEntryRsp` /
`g_AsmCycleCount` in the debugger, or the metric buffer PING exposes.
A thread that never reaches its first cycle stays silent by design (on
oversubscribed hosts the first schedule can lag far behind any timeout
without anything being wrong); `WorkerStop` still tears everything down,
since a late-waking thread observes the stop on its first pass and
terminates itself. Verification is offline, from the recorded stream.

## The descriptor trick: Windows' GDT, a null TR

There is no private GDT. The block reuses the native GDTR verbatim, so
the gadget's `LGDT` reloads the Windows GDT that is already valid on the
pinned CPU. Only the IDT is custom, and only TR is crafted, and the
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
selector can never be loaded into TR. Error code 0, vector 13: the
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
| 13 | `AsmGpStub` | yes, expected: code 0 |
| 18 | `AsmMcStub` | no, record + `MACHINE_CHECK_EXCEPTION` |
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
code. Anything else under the custom IDT means this driver, not
Windows, is at fault: hence bugcheck, never guess.

## The APIC window and the NMI handler

Mode detection runs once at setup (`Apic.cpp`): CPUID.1 ECX[21] for x2APIC
support plus the `ENABLE_X2APIC` bit in `IA32_APIC_BASE`. x2APIC mode needs
nothing mapped; xAPIC mode maps the 4K register page non-cached for the
ICR pair. Setup also captures the pinned CPU's hardware APIC ID from
xAPIC register `+0x20` (bits 31:24) or x2APIC MSR `0x802` (all 32 bits).
Both loop and synthetic NMIs explicitly address that physical ID with
ICR low `0x400`: NMI delivery, edge trigger, no destination shorthand.
The Windows processor number is not used as an APIC ID. The assembly send
macros keep each `Committed` marker immediately after the issuing write:

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

The pause batch is 20000 iterations (`APIC_PAUSE_ITERATIONS`), with a stop
check once per batch before reissuing. A disarmed dwell pause (default
4100 pauses, `APIC_DWELL_PAUSES_BALANCED`; 42000 in the deep operating
point) runs once per cycle before the first ICR write, extending the
period without extending the armed window. The dwell count is tunable at
runtime through `g_AsmDwellIters`.

The NMI stub reads the interrupted RIP from its own trap frame and
compares it against `[Committed, End)` of the active mode. Three paths:

- **Transparent**: no entry RSP stashed yet. The #GP stub has not run, so
  this NMI landed in the first instructions of the first cycle and no
  request of ours could have completed: it is foreign. One synthetic
  self-NMI, then `IRETQ` back to the interrupted context unchanged (no
  restore: the custom IDT must stay loaded). The synthetic is consumed
  under the custom IDT as the prologue completes, so this path can never
  reach native.
- **Expected**: RIP inside the window. The delivery is consumed as our own
  request. Shared teardown and reentry.
- **Foreign**: RIP outside the window with the protocol up. Genuinely
  foreign: post-stash, no request of ours can be outstanding outside the
  loop, so this cannot be a misclassified self-NMI. On the target that is
  an ICR-sent NMI from Windows or a similar agent, sourceless by
  construction exactly like our own. Recorded as the unexpected vector-2
  delivery it is (the `NmiEntry` sibling carries the interrupted RIP for
  offline judging), then answered with exactly one synthetic self-NMI: the
  design's only allowed crosser. It is consumed natively right after the
  shared teardown's restore + `iretq`: it cannot age past the entry
  sliver, a latched NMI is recognized at the first post-`iretq`
  boundary while the IDT is still native, where the sender's expecting
  NMI callback claims it, timing intact to microseconds and
  indistinguishable from the original to any check the protocol could
  run. If nothing claims it, Windows answers with
  `NMI_HARDWARE_FAILURE`; that outcome proves an unclaimed foreign
  arrived and is the accepted cost of the reinjection requirement.

The honest table: what each delivery costs Windows:

| Delivery | Windows receives |
| --- | --- |
| self-NMI, nothing foreign near | nothing (consumed; it was ours) |
| foreign before our write | the synthetic, natively: claimed by the sender's callback, or bugcheck if unclaimed |
| foreign inside our window | nothing (coalesced; see below) |
| foreign in prologue/tail | the synthetic, natively: same claimed-or-crash contract |
| level-latched hardware source | its own redelivery, natively, on top of the above |
| stop requested | the terminating thread is gone; drains leave nothing pending |

> [!NOTE]
> The coalescing bound (deliberate, documented, not fixable inside this
> scheme): "NMI pending" is one architectural latch, not a count. A foreign
> NMI raised between our ICR write and its delivery merges with ours into
> a single delivery, which the RIP test consumes as expected. If no second
> request stayed latched, the foreign event never reaches Windows. The RIP
> window identifies interrupted *code*, and no observation available inside
> the handler identifies the *source*: an NMI carries none.
>
> And the hard rule underneath it: the only crosser the design allows is
> the deliberate synthetic answer to a consumed foreign. Loop issues
> never cross: issues happen only at the loop top, every delivery is
> consumed in a stub, and the stop paths drain rather than terminate
> over a pending request. A loop issue crossing instead, sourceless and
> unowned, is answered by Windows with `NMI_HARDWARE_FAILURE`.

## Reentry: abandon, never resume

The teardown restores the natives first: `LIDT`/`LGDT` native, then CR8 0
(order matters: pending interrupts must find the native IDT the moment
they unmask). Then it records, counts the cycle, patches its *own* NMI
frame into a reentry frame, and executes `IRETQ`, which also unblocks
further NMIs:

| Frame slot | Value |
| --- | --- |
| RIP | gadget address (`g_AsmRoutine`) |
| CS / SS | native selectors |
| RFLAGS | interrupted RFLAGS with IF forced on |
| RSP | stashed entry RSP (`g_AsmEntryRsp`) |
| RCX | block (set explicitly: `IRETQ` does not restore RCX) |

The interrupted context (pause loop, fault frame, stub pushes) is
abandoned by switching RSP: frames never accumulate. The entry RSP is
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
  |
  v
mov cr0/cr3/cr4 .............. same-value rewrites, PASSIVE, native IDT
mov cr8, 15 .................. mask everything (TPR)
lgdt native / lidt custom
and [GdtBase+5], ~2 .......... no-op on the null descriptor
ltr 0 ........................ #GP(0), expected
  |
  v
#GP stub: stash entry RSP ---> APIC_WRITE
  |                                |
  |                           ICR write (self-NMI)
  |                           Committed: <-- marker
  |                                | pause batches, stop check, reissue
  |                                v
  |                           NMI arrives
  |                                |
  |               +----------------+----------------+
  |               v                v                v
  |          transparent       expected          foreign
  |          (no stash)       (in window)     (out of window)
  |          synthetic +      consume,        synthetic +
  |          iret to ctx      teardown        shared teardown
  |          (custom-                         (crosses natively,
  |           consumed)                        callback claims)
  |               |                |                |
  |               |                v                v
  |               |         restore natives, CR8 = 0
  |               |         iretq --> RIP = gadget,
  |               |                   RCX = block, RSP = entry RSP
  |               |                   (stop: terminate instead)
  v               v
 (transparent path rejoins the #GP stub; the loop continues)
```

## Load pipeline: sweep, window, mailbox, worker

Everything happens in `DriverEntry`, in this order, and any failure
refuses the load with nothing running:

1. **Discovery** (`Restore.cpp`): resolve `KiRestoreProcessorControlState`
   in the loaded kernel image, exactly one signature match.
2. **Sweep** (`Sweep.cpp`): terminate threads left parked inside the
   gadget by a previous instance that died without unloading. The System
   process (PID 4) is walked with `ZwGetNextThread`; a thread whose start
   address equals the gadget base gets a kernel-mode termination APC.
   Passes repeat until a full walk observes nothing (at most 50 passes,
   100 ms apart); leftovers fail the load with `STATUS_TIMEOUT`.
3. **Window** (`Physical.cpp`): allocate one contiguous page (so its PTE
   is exclusive), discover the PTE-array base by scanning the live PML4
   for its self-reference entry (CR3 is read attached to System, the
   frame is read with `MmCopyMemory`, `MmMapIoSpace` is only a fallback),
   then force the window's PTE present and writable.
4. **Mailbox** (`SharedMemoryHandler.cpp`): consume the registry
   rendezvous (see below), MDL-lock the consumer's 8192-byte buffer with
   a user-mode probe, map it into system space, publish it for the NMI
   side, answer `Status = OK` through the mapping, and delete the
   registry value so a stale blob can never be consumed twice.
5. **Worker** (`Worker.cpp`): pin, detect APIC mode, capture the CPU's
   native descriptor state, publish everything to the assembly protocol,
   and create the thread born inside the gadget. Cycling is not awaited
   (see above).

`DriverUnload` stops in reverse: signal the worker and wait for its last
cycle to tear down, drop the mailbox, release the window.

## Consumer and transport

`User/main.cpp` is the reference consumer and the only transport that
exists. Bring-up order (the driver handshakes once, in `DriverEntry`, so
the consumer must exist first):

1. `VirtualAlloc` exactly 8192 bytes, fill mailbox/message magics, set
   `Status = NONE`, record a nonce.
2. Write one `SHM_HANDSHAKE` blob (magic, nonce, PID, user VA, size) as
   `REG_BINARY` to `HKLM\SOFTWARE\MmDiag\Rendezvous`.
3. Create and start the `nmi-immunity` service with the sys path
   (`User.exe <full-path-to-nmi-immunity.sys>`). `StartService` returning
   means `DriverEntry` ran; a refusal surfaces driver validation
   directly. Then poll the mailbox for the handshake answer (20 s): it
   must read `Status = OK` with the nonce echoed.
4. Submit `PING` / `READ_PHYS` / `WRITE_PHYS` one at a time: fill the
   message, barrier, set `Pending = 1` last, poll `Pending == 0`
   (5 s per request), barrier, read `Status` and data. The PING payload
   reports the CR8 sampled while serving (15 proves `HIGH_LEVEL`) plus
   cycle, issue, served, and uptime counters.

The full contract lives in `Shared/Communication.h`. Its limits are the
PoC's limits: one consumer, polling completion, admin-only registry
writes, teardown by convention. See the [transport section](#poc-disclaimer)
for what a real channel requires.

## Stop, unload, and what the debugger shows

`WorkerStop` sets the flag. The thread observes it on its current cycle:
at the next NMI teardown, or inside the next `APIC_WRITE` batch, whose
stop check terminates from the #GP frame. Both stop paths restore the
natives, record `StopRequested`, and call `PsTerminateSystemThread` on the
clean entry stack (native IDT, CR8 passive: an ordinary call again).
`WorkerStop` waits on the thread object without a timeout: the thread is
guaranteed one cycle out. Then it dumps the event history, frees the IDT
and block, unmaps the xAPIC window, and releases the thread objects.
Freeing before the wait would pull the IDT out from under a live handler;
the wait is what makes the teardown order safe.

Three output channels, strictly separated by execution context:

- **Text** (`Debug.h`: `KmError`/`KmWarning`/`KmPrint`/`KmTrace` over
  `DbgPrintEx`, `DPFLTR_IHVDRIVER_ID`, checked builds only): setup,
  teardown, lifecycle: `PASSIVE_LEVEL` with native tables. Never called
  from the custom window.
- **Event recorder** (`Trace.h`: `KM_EVENT_BUFFER`, 256 append-only numeric
  records, lock-free single-attempt reservation so a nested NMI producer
  can never wait): everything observed while the custom IDT is loaded.
  Dumped once, after the thread died, via `KmEventDump`. A full or
  contended buffer drops diagnostics and says so; dispatch never depends
  on recording.
- **Metric recorder** (`Trace.h`: `KM_METRIC_BUFFER`, 16384 records,
  always on independently of `DBG`): one 64-byte record per NMI delivery
  (TSC, sequence, cycle, issue, RIP/RSP, classification flags). This is
  the offline-judging instrument: loss and rate claims are checked
  against it, never trusted from counters alone.

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
| `Kernel/Apic.h` / `Kernel/Apic.cpp` | xAPIC/x2APIC detection + xAPIC mapping |
| `Kernel/Asm.h` / `Kernel/Asm.asm` | stubs, `APIC_WRITE` windows + markers, teardown / reentry / terminate, GDTR read |
| `Kernel/Debug.h` / `Kernel/Debug.cpp` | checked-build text emitter (`PASSIVE_LEVEL` only) |
| `Kernel/Entry.h` / `Kernel/Entry.cpp` | `DriverEntry` / `DriverUnload` wiring |
| `Kernel/KmModule.h` / `Kernel/KmModule.cpp` | module list + executable-section scan |
| `Kernel/Physical.h` / `Kernel/Physical.cpp` | contiguous window + PTE-base discovery |
| `Kernel/Restore.h` / `Kernel/Restore.cpp` | gadget signature discovery |
| `Kernel/SharedMemoryHandler.h` / `Kernel/SharedMemoryHandler.cpp` | registry rendezvous + mailbox, NMI request serving |
| `Kernel/Sweep.h` / `Kernel/Sweep.cpp` | stale gadget-thread sweep at load |
| `Kernel/Tables.h` / `Kernel/Tables.cpp` | native capture, custom IDT, RCX block |
| `Kernel/Trace.h` / `Kernel/Trace.cpp` | bounded event + metric recorders, asm forwarder |
| `Kernel/Worker.h` / `Kernel/Worker.cpp` | pin, setup, direct birth, stop |
| `Shared/Communication.h` | the kernel/user wire contract (mailbox, handshake, requests) |
| `User/main.cpp` (`User/User.vcxproj`) | reference consumer: rendezvous, load, PING / READ_PHYS / WRITE_PHYS demo |
| `Kernel/nmi-immunity.inf` | primitive service INF (no devices) |
| `Kernel/Kernel.vcxproj` / `.filters` | driver build |

## Building

Needs the WDK and a matching Visual Studio. The project is x64-only by
design (CR8, `LGDT`/`LIDT`, MSR interfaces, MASM); there are no ARM64
configs.

```
msbuild nmi-immunity.slnx -p:Configuration=Debug   -p:Platform=x64
msbuild nmi-immunity.slnx -p:Configuration=Release -p:Platform=x64
```

Debug/Release x64 builds with zero warnings and is
PREfast-clean. If package verification fails on a missing `InfVerif.dll`,
that is a broken WDK install on the build machine (it fails the same way
for any driver there); pass `-p:SkipPackageVerification=true` for local
iteration only: never bake it into the project.

Loading needs test signing on the target. Two ways to load: the reference
consumer (`User.exe <full-path-to-nmi-immunity.sys>`, which writes the
rendezvous and starts the service itself), or the INF directly (install
the driver package, then `sc start nmi-immunity`; `sc stop nmi-immunity`
to end, which takes one cycle at most). The INF path loads the driver
without a mailbox: the handshake fails the load, since a boot without a
consumer would leave the channel deaf.

Machine notes: the VSL/HyperV branch inside the gadget is assumed never
taken: discovery finds bytes, it cannot check runtime flags, so VBS /
Hyper-V-rooted hosts are out of scope. The pinned CPU is hogged but not
hung: pending work drains in every cycle's passive windows, and
preemption in the entry sliver only delays. Group-0-only pinning; a first
processor elsewhere fails load.

## License

Released under the MIT license.
