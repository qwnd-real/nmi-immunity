#pragma once

#include <ntifs.h>
#include "../Shared/Communication.h"

/*++

Module Name:

    SharedMemoryHandler.h

Abstract:

    This module declares the mailbox that shares memory between the
    NMI handler and one user-mode consumer, with no device object, no
    section, no handle and no VAD created by the driver.

    Handshake (DriverEntry, PASSIVE_LEVEL): the consumer pre-allocates
    SHM_MAILBOX_BYTES, writes an SHM_HANDSHAKE blob to the rendezvous
    value and loads the driver. ShmHandshake consumes the blob, locks
    the consumer's pages with an MDL, maps them into system space and
    publishes the mapping. The mailbox is mandatory: a missing or
    malformed blob fails the load.

    Requests (steady state): the consumer submits into the mailbox and
    the NMI stub calls ShmHandleRequest on every HIGH_LEVEL delivery
    with a request pending. PING, READ_PHYS and WRITE_PHYS are served
    through the Physical window.

--*/

/*++

    IRQL CONTRACT -- READ THIS BEFORE TOUCHING ANYTHING BELOW.

    ShmHandleRequest executes at HIGH_LEVEL (x64 IRQL 15), inside the
    NMI handler, with interrupts disabled on the pinned CPU. The
    assembly stub enforces this dynamically: it reads CR8 and skips
    the call unless CR8 == 15. Nothing about that context supports
    ordinary kernel programming:

        - No page faults. Every byte touched must be resident
          non-paged: the mailbox mapping (wired by the MDL), the
          Physical window state, and resident code. A single paged
          touch bugchecks the box.

        - No kernel services. No Mm*, no Ex* (including pool), no
          Ke* waits or locks, no Ob*, no Zw*, no DbgPrintEx, nothing
          in Debug.h. Those either page, block, or take locks, and
          all three are fatal at HIGH_LEVEL.

        - No foreign calls at all, with exactly four exceptions, each
          HIGH_LEVEL-safe by construction and documented as such:
          PhysicalSetBacking and PhysicalGetWindow (the resident PTE
          window: one volatile store plus INVLPG), RtlCopyMemory
          (inline copy, no fault possible on resident pages), and
          KeMemoryBarrier (compiler plus hardware fence only).

        - No unbounded work. Transfers are capped by
          SHM_MAX_TRANSFER, so one request touches at most two
          physical frames and returns.

    The PASSIVE_LEVEL half of this module (ShmHandshake and
    ShmUninitialize, both in PAGE) follows ordinary rules and may use
    the full kernel API. The two halves share only the published
    mapping globals, handed over with barriers.

--*/

//
// Handshake: consume the rendezvous blob, lock the consumer's mailbox
// and publish the mapping for the NMI side. Fails the load on a
// missing blob, a malformed blob, an unresolvable process, or an
// un-lockable buffer. Must run before the worker is born: the first
// NMI delivery may already carry a request.
//

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
ShmHandshake(
    VOID
);

//
// Teardown: unpublish first (with barriers, so an in-flight NMI
// observes the teardown), then unmap, unlock and free the MDL. Runs
// after the worker has stopped, so no NMI can be in flight.
//

_IRQL_requires_(PASSIVE_LEVEL)
VOID
ShmUninitialize(
    VOID
);

//
// NMI service entry. See the IRQL contract above: HIGH_LEVEL only,
// allowlisted calls only, bounded work only. The assembly stub passes
// the published mailbox address and guarantees CR8 == 15.
//

EXTERN_C_START

_IRQL_requires_(HIGH_LEVEL)
VOID
ShmHandleRequest(
    _In_ PVOID Mailbox
);

EXTERN_C_END
