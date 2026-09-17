#pragma once

//
// wdm.h, reached through ntifs.h, already includes dpfilter.h, which has no
// include guard. Keep the common kernel includes here so every caller sees
// the same status definitions and debugger filter constants.
//

#include <ntifs.h>
#include <ntstrsafe.h>

/*++

Module Name:

    Debug.h

Abstract:

    This module declares the debug printing infrastructure used by every
    component of the driver.

    Checked builds print; free builds compile the call sites away, arguments
    and all, so a trace call costs nothing in retail.

    Output goes to DbgPrintEx under DPFLTR_IHVDRIVER_ID with a real severity
    level, so the debugger can filter it without a rebuild:

        kd> ed nt!Kd_IHVDRIVER_Mask 0xF     // error, warning, trace, info

    Text output belongs to setup, teardown and diagnostic draining, while
    the native Windows descriptor tables and a normal thread stack are in
    use. This project's text emitter is deliberately restricted to
    PASSIVE_LEVEL. An IRQL value alone does not establish that the current
    execution context is suitable for a debugger call.

    The custom descriptor window, exception entry, NMI entry and return
    assembly must use the bounded recorder in Trace.h instead. That path
    records numeric observations for later printing; it never formats text
    or calls the debugger. A dropped diagnostic must not affect dispatch.

--*/

#if DBG

_IRQL_requires_(PASSIVE_LEVEL)
VOID
KmTraceWrite(
    _In_ ULONG Level,
    _In_ CHAR Tag,
    _In_z_ PCSTR FunctionName,
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
);

#define KmTracePrint(Level, Tag, ...) \
    KmTraceWrite((Level), (Tag), __FUNCTION__, __VA_ARGS__)

#else

//
// __noop discards the call without evaluating anything, yet still counts as a
// use of every argument, so a variable that only feeds a trace does not become
// an unreferenced local in retail.
//

#define KmTracePrint(Level, Tag, ...) __noop(__VA_ARGS__)

#endif

#define KmError(...)    KmTracePrint(DPFLTR_ERROR_LEVEL, 'E', __VA_ARGS__)
#define KmWarning(...)  KmTracePrint(DPFLTR_WARNING_LEVEL, 'W', __VA_ARGS__)
#define KmPrint(...)    KmTracePrint(DPFLTR_INFO_LEVEL, 'I', __VA_ARGS__)
#define KmTrace(...)    KmTracePrint(DPFLTR_TRACE_LEVEL, 'T', __VA_ARGS__)

PCSTR
KmStatusToString(
    _In_ NTSTATUS Status
);
