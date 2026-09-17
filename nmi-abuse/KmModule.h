#pragma once

#include <ntifs.h>
#include <ntimage.h>

/*++

Module Name:

    KmModule.h

Abstract:

    This module declares a small utility interface over the loaded kernel
    module list: it resolves the load address and size of a driver by
    name, and it scans a loaded module's executable sections for a byte
    pattern.

    The module list is read through ZwQuerySystemInformation with
    SystemModuleInformation. The class and its record layout are
    stable since the first NT release, but they are not part of the
    documented WDK surface, so both are declared locally and every value
    that comes back is validated before it is used.

--*/

//
// Upper bound for the module list buffer. The list covers every loaded
// kernel component; a few thousand entries is far beyond any real machine,
// and the bound exists so a corrupted length cannot drive the allocation.
//

#define KM_MODULE_MAX_LIST_SIZE         (1024 * 1024)

//
// Ceiling on the number of sections accepted while parsing a loaded image,
// for the same reason.
//

#define KM_MODULE_MAX_SECTIONS          96

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
KmModuleQueryInfo(
    _In_z_ PCWSTR DriverName,
    _Out_opt_ PULONG64 ImageBase,
    _Out_opt_ PULONG ImageSize
);

/*++

Routine Description:

    Scans the executable sections of a loaded module for a byte pattern
    and reports a match only when exactly one eligible address matches.

    Eligible sections are readable, executable and not discardable. PAGE*
    and INIT* sections are excluded by name. This establishes a resident
    code candidate in the native kernel image; it does not establish a
    callable ABI, a function boundary or the semantics of later instructions.

Arguments:

    ImageBase - Load address of the module, as reported by
        KmModuleQueryInfo.

    ImageSize - Size of the module in bytes, as reported by
        KmModuleQueryInfo.

    Pattern - The bytes to look for.

    PatternLength - Number of bytes in Pattern.

    MatchAddress - Receives the unique match, or zero on every failure.

Return Value:

    STATUS_SUCCESS - Exactly one eligible match was found and reported.

    STATUS_NOT_FOUND - The image parsed, but no section contains the
        pattern.

    STATUS_OBJECT_NAME_COLLISION - Multiple eligible matches were found.

    Any failure status from parsing the image headers.

--*/

_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
KmModuleFindPattern(
    _In_ ULONG64 ImageBase,
    _In_ ULONG ImageSize,
    _In_reads_bytes_(PatternLength) const UCHAR* Pattern,
    _In_ ULONG PatternLength,
    _Out_ PULONG64 MatchAddress
);
