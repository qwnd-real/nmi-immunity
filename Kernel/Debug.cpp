#include "Debug.h"

/*++

Module Name:

    Debug.cpp

Abstract:

    This module implements the debug printing infrastructure declared in
    Debug.h. The emitter preserves disk-comm's severity tags, function
    prefix, filter component and checked-build behavior. It exists only
    in checked builds and requires normal Windows execution context at
    PASSIVE_LEVEL; the underlying debugger may synchronize with other
    processors, even though this wrapper takes no locks itself.

    Trace.cpp provides the separate memory recorder for observations made
    while descriptor state belongs to nmi-immunity. Its dump routine is
    the only bridge from those observations back to this text emitter.

--*/

typedef struct _KM_STATUS_ENTRY
{
    NTSTATUS Status;
    PCSTR Name;
} KM_STATUS_ENTRY, *PKM_STATUS_ENTRY;

//
// Common setup and lifecycle statuses. Retaining the reference project's
// table keeps status formatting consistent across the two drivers. Anything
// outside the table is reported numerically by the caller.
//

static const KM_STATUS_ENTRY KmStatusTable[] =
{
    { STATUS_SUCCESS,                   "STATUS_SUCCESS" },
    { STATUS_PENDING,                   "STATUS_PENDING" },
    { STATUS_TIMEOUT,                   "STATUS_TIMEOUT" },
    { STATUS_BUFFER_OVERFLOW,           "STATUS_BUFFER_OVERFLOW" },
    { STATUS_NO_MORE_ENTRIES,           "STATUS_NO_MORE_ENTRIES" },
    { STATUS_NOT_FOUND,                 "STATUS_NOT_FOUND" },
    { STATUS_UNSUCCESSFUL,              "STATUS_UNSUCCESSFUL" },
    { STATUS_NOT_IMPLEMENTED,           "STATUS_NOT_IMPLEMENTED" },
    { STATUS_INVALID_PARAMETER,         "STATUS_INVALID_PARAMETER" },
    { STATUS_INFO_LENGTH_MISMATCH,      "STATUS_INFO_LENGTH_MISMATCH" },
    { STATUS_DATA_ERROR,                "STATUS_DATA_ERROR" },
    { STATUS_INVALID_IMAGE_FORMAT,      "STATUS_INVALID_IMAGE_FORMAT" },
    { STATUS_INVALID_IMAGE_PROTECT,     "STATUS_INVALID_IMAGE_PROTECT" },
    { STATUS_OBJECT_NAME_COLLISION,     "STATUS_OBJECT_NAME_COLLISION" },
    { STATUS_NO_SUCH_DEVICE,            "STATUS_NO_SUCH_DEVICE" },
    { STATUS_INVALID_DEVICE_REQUEST,    "STATUS_INVALID_DEVICE_REQUEST" },
    { STATUS_BUFFER_TOO_SMALL,          "STATUS_BUFFER_TOO_SMALL" },
    { STATUS_OBJECT_NAME_NOT_FOUND,     "STATUS_OBJECT_NAME_NOT_FOUND" },
    { STATUS_OBJECT_NAME_INVALID,       "STATUS_OBJECT_NAME_INVALID" },
    { STATUS_OBJECT_PATH_NOT_FOUND,     "STATUS_OBJECT_PATH_NOT_FOUND" },
    { STATUS_DELETE_PENDING,            "STATUS_DELETE_PENDING" },
    { STATUS_ACCESS_DENIED,             "STATUS_ACCESS_DENIED" },
    { STATUS_INSUFFICIENT_RESOURCES,    "STATUS_INSUFFICIENT_RESOURCES" },
    { STATUS_DEVICE_NOT_CONNECTED,      "STATUS_DEVICE_NOT_CONNECTED" },
    { STATUS_DEVICE_DOES_NOT_EXIST,     "STATUS_DEVICE_DOES_NOT_EXIST" },
    { STATUS_DEVICE_BUSY,               "STATUS_DEVICE_BUSY" },
    { STATUS_DEVICE_REMOVED,            "STATUS_DEVICE_REMOVED" },
    { STATUS_NO_MEDIA_IN_DEVICE,        "STATUS_NO_MEDIA_IN_DEVICE" },
    { STATUS_IO_TIMEOUT,                "STATUS_IO_TIMEOUT" },
    { STATUS_IO_DEVICE_ERROR,           "STATUS_IO_DEVICE_ERROR" },
    { STATUS_CANCELLED,                 "STATUS_CANCELLED" },
    { STATUS_NOT_SUPPORTED,             "STATUS_NOT_SUPPORTED" },
    { STATUS_INVALID_DEVICE_STATE,      "STATUS_INVALID_DEVICE_STATE" },
    { STATUS_INVALID_BUFFER_SIZE,       "STATUS_INVALID_BUFFER_SIZE" }
};

_Use_decl_annotations_
PCSTR
KmStatusToString(
    NTSTATUS Status
)
/*++

Routine Description:

    Translates an NTSTATUS into its symbolic name for log readability.

Arguments:

    Status - The status value to translate.

Return Value:

    A static, never NULL, string. Unknown codes translate to "STATUS_?", and
    callers are expected to also log the numeric value.

--*/
{
    ULONG Index;

    for (Index = 0; Index < RTL_NUMBER_OF(KmStatusTable); Index += 1)
    {
        if (KmStatusTable[Index].Status == Status)
        {
            return KmStatusTable[Index].Name;
        }
    }

    return "STATUS_?";
}

#if DBG

_Use_decl_annotations_
VOID
KmTraceWrite(
    ULONG Level,
    CHAR Tag,
    PCSTR FunctionName,
    PCSTR Format,
    ...
)
/*++

Routine Description:

    Emits one formatted debug message, prefixed with the severity tag and the
    emitting routine.

Arguments:

    Level - A DPFLTR_*_LEVEL severity.

    Tag - Single character severity marker.

    FunctionName - Name of the emitting routine, normally __FUNCTION__.

    Format - printf style format string, expected to end with a newline.

    ... - Format arguments.

Return Value:

    None. Debug output is best effort and its failure is never propagated.

--*/
{
    CHAR Prefix[96];
    va_list ArgumentList;

    //
    // RtlStringCchPrintfA always NUL terminates, including on truncation, so
    // the return value carries no information worth acting on here.
    //

    (VOID)RtlStringCchPrintfA(
        Prefix,
        RTL_NUMBER_OF(Prefix),
        "[nmi-immunity] %c %s: ",
        Tag,
        FunctionName
    );

    va_start(ArgumentList, Format);

    (VOID)vDbgPrintExWithPrefix(
        Prefix,
        DPFLTR_IHVDRIVER_ID,
        Level,
        Format,
        ArgumentList
    );

    va_end(ArgumentList);
}

#endif
