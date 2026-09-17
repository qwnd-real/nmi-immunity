#include "KmModule.h"
#include "Debug.h"

/*++

Module Name:

    KmModule.cpp

Abstract:

    This module implements the loaded module utility declared in KmModule.h.

    The module list is fetched with ZwQuerySystemInformation, whose module
    record layout is mirrored locally because the WDK headers no longer
    declare it. The image scan parses the in-memory PE headers of the
    target module and walks readable, executable, resident sections. A
    pattern must have exactly one eligible match before its address is
    returned. Discovery establishes a candidate; its execution contract
    belongs to Restore.cpp and the eventual state-management modules.

--*/

#define KM_MODULE_POOL_TAG              'lMiN'

//
// SystemModuleInformation. The enum value is not declared for drivers, but
// the information class itself has been stable since the first NT release.
//

#define KM_MODULE_INFORMATION_CLASS     11

//
// ZwQuerySystemInformation. Exported by ntoskrnl, but no longer declared
// in the driver headers, so the prototype is mirrored here.
//

EXTERN_C_START

NTKERNELAPI
NTSTATUS
ZwQuerySystemInformation(
    _In_ ULONG SystemInformationClass,
    _Inout_ PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

EXTERN_C_END

/*++

Structure Description:

    One entry of the SystemModuleInformation list, mirroring the
    RTL_PROCESS_MODULE_INFORMATION layout: a naturally aligned record of image base,
    image size and the full path, with the file name beginning at
    OffsetToFileName inside FullPathName.

--*/

typedef struct _KM_MODULE_LIST_ENTRY
{
    PVOID Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR FullPathName[256];
} KM_MODULE_LIST_ENTRY, *PKM_MODULE_LIST_ENTRY;

/*++

Structure Description:

    The SystemModuleInformation reply: a count followed by that many
    naturally aligned entries. The padding before Modules is part of the ABI.

--*/

typedef struct _KM_MODULE_LIST
{
    ULONG NumberOfModules;
    KM_MODULE_LIST_ENTRY Modules[ANYSIZE_ARRAY];
} KM_MODULE_LIST, *PKM_MODULE_LIST;

//
// Forward declarations for internal helper functions
//

static
BOOLEAN
KmModuleMatchName(
    _In_z_ PCWSTR DriverName,
    _In_reads_(NameLength) PCSTR ModuleName,
    _In_ ULONG NameLength
);

static
CHAR
KmModuleLowerAnsi(
    _In_ CHAR Character
);

static
WCHAR
KmModuleLowerWide(
    _In_ WCHAR Character
);

#pragma code_seg(push)
#pragma code_seg("PAGE")

static
CHAR
KmModuleLowerAnsi(
    _In_ CHAR Character
)
/*++

Routine Description:

    Lowercases one ASCII character.

Arguments:

    Character - The character.

Return Value:

    The lowercased character.

--*/
{
    PAGED_CODE();

    if ((Character >= 'A') && (Character <= 'Z'))
    {
        return (CHAR)(Character + ('a' - 'A'));
    }

    return Character;
}

static
WCHAR
KmModuleLowerWide(
    _In_ WCHAR Character
)
/*++

Routine Description:

    Lowercases one wide character of the ASCII range.

Arguments:

    Character - The character.

Return Value:

    The lowercased character.

--*/
{
    PAGED_CODE();

    if ((Character >= L'A') && (Character <= L'Z'))
    {
        return (WCHAR)(Character + (L'a' - L'A'));
    }

    return Character;
}

_Use_decl_annotations_
static
BOOLEAN
KmModuleMatchName(
    PCWSTR DriverName,
    PCSTR ModuleName,
    ULONG NameLength
)
/*++

Routine Description:

    Compares a requested driver name, for example L"storport.sys", against
    one module's file name, case insensitively.

Arguments:

    DriverName - The requested name, NUL terminated.

    ModuleName - The module's file name, not necessarily NUL terminated.

    NameLength - Number of characters available in ModuleName.

Return Value:

    TRUE when the names match.

--*/
{
    ULONG Index;

    PAGED_CODE();

    Index = 0;

    while ((DriverName[Index] != L'\0') && (Index < NameLength))
    {
        if (KmModuleLowerWide(DriverName[Index]) !=
            (WCHAR)KmModuleLowerAnsi(ModuleName[Index]))
        {
            return FALSE;
        }

        Index += 1;
    }

    if (DriverName[Index] != L'\0')
    {
        return FALSE;
    }

    if ((Index < NameLength) && (ModuleName[Index] != '\0'))
    {
        //
        // The requested name is a proper prefix of the module's name, for
        // example "storport" against "storportx.sys": not a match.
        //

        return FALSE;
    }

    return TRUE;
}

_Use_decl_annotations_
NTSTATUS
KmModuleQueryInfo(
    PCWSTR DriverName,
    PULONG64 ImageBase,
    PULONG ImageSize
)
/*++

Routine Description:

    Resolves the load address and size of a loaded driver by name.

Arguments:

    DriverName - The driver's file name, for example L"storport.sys".

    ImageBase - Optionally receives the load address.

    ImageSize - Optionally receives the image size in bytes.

Return Value:

    STATUS_SUCCESS - The module was found and reported.

    STATUS_NOT_FOUND - No loaded module carries that name.

    STATUS_INFO_LENGTH_MISMATCH - The module list could not be captured
        within the size bound.

    Any other failure status from ZwQuerySystemInformation.

--*/
{
    PKM_MODULE_LIST ModuleList;
    PKM_MODULE_LIST_ENTRY Entry;
    NTSTATUS Status;
    ULONG BufferSize;
    ULONG Returned;
    ULONG Index;
    ULONG NameLength;
    ULONG Attempt;

    PAGED_CODE();

    if (ImageBase != NULL)
    {
        *ImageBase = 0;
    }

    if (ImageSize != NULL)
    {
        *ImageSize = 0;
    }

    ModuleList = NULL;
    BufferSize = 64 * 1024;

    //
    // The list is fetched with a growing buffer. Only growth is retried;
    // any other failure is reported at once.
    //

    for (Attempt = 1; ; Attempt += 1)
    {
        ModuleList = (PKM_MODULE_LIST)ExAllocatePool2(
            POOL_FLAG_NON_PAGED,
            BufferSize,
            KM_MODULE_POOL_TAG
        );

        if (ModuleList == NULL)
        {
            KmError("Failed to allocate a %u byte module list\n", BufferSize);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        Returned = 0;

        Status = ZwQuerySystemInformation(
            KM_MODULE_INFORMATION_CLASS,
            ModuleList,
            BufferSize,
            &Returned
        );

        if (NT_SUCCESS(Status))
        {
            break;
        }

        ExFreePoolWithTag(ModuleList, KM_MODULE_POOL_TAG);
        ModuleList = NULL;

        if ((Status != STATUS_INFO_LENGTH_MISMATCH) ||
            (Returned <= BufferSize) ||
            (Returned > KM_MODULE_MAX_LIST_SIZE) ||
            (Attempt >= 4))
        {
            KmError("Module list query failed - Status=%s (0x%08X)\n",
                KmStatusToString(Status), Status);
            return Status;
        }

        BufferSize = Returned;
    }

    //
    // Every length that governs the walk is validated against the buffer
    // before it is used, the same as any other foreign data.
    //

    if ((Returned < FIELD_OFFSET(KM_MODULE_LIST, Modules)) ||
        (Returned > BufferSize) ||
        (ModuleList->NumberOfModules == 0) ||
        (ModuleList->NumberOfModules >
            ((Returned - FIELD_OFFSET(KM_MODULE_LIST, Modules)) /
             sizeof(KM_MODULE_LIST_ENTRY))))
    {
        KmWarning("Module list is truncated or empty\n");
        ExFreePoolWithTag(ModuleList, KM_MODULE_POOL_TAG);
        return STATUS_DATA_ERROR;
    }

    for (Index = 0; Index < ModuleList->NumberOfModules; Index += 1)
    {
        Entry = &ModuleList->Modules[Index];

        if ((Entry->ImageBase == NULL) || (Entry->ImageSize == 0))
        {
            continue;
        }

        if (Entry->OffsetToFileName >= RTL_NUMBER_OF(Entry->FullPathName))
        {
            continue;
        }

        NameLength = RTL_NUMBER_OF(Entry->FullPathName) -
                     Entry->OffsetToFileName;

        if (!KmModuleMatchName(
                DriverName,
                &Entry->FullPathName[Entry->OffsetToFileName],
                NameLength))
        {
            continue;
        }

        KmTrace("Module %ws found - Base=%p Size=0x%X\n",
            DriverName, Entry->ImageBase, Entry->ImageSize);

        if (ImageBase != NULL)
        {
            *ImageBase = (ULONG64)(ULONG_PTR)Entry->ImageBase;
        }

        if (ImageSize != NULL)
        {
            *ImageSize = Entry->ImageSize;
        }

        ExFreePoolWithTag(ModuleList, KM_MODULE_POOL_TAG);
        return STATUS_SUCCESS;
    }

    ExFreePoolWithTag(ModuleList, KM_MODULE_POOL_TAG);

    KmError("Module %ws is not loaded\n", DriverName);
    return STATUS_NOT_FOUND;
}

_Use_decl_annotations_
NTSTATUS
KmModuleFindPattern(
    ULONG64 ImageBase,
    ULONG ImageSize,
    const UCHAR* Pattern,
    ULONG PatternLength,
    PULONG64 MatchAddress
)
/*++

Routine Description:

    Finds a unique byte pattern in resident executable sections of a loaded
    PE32+ image. All bounds use the module-list image extent; a second match
    is an error, even if the first address looks plausible in the debugger.

    The scan walks in-memory PE headers and returns a virtual address. The
    caller owns image lifetime and must establish the candidate's execution
    contract separately; a byte match alone is not permission to call it.

Arguments:

    ImageBase - Load address of the module.

    ImageSize - Size of the module in bytes.

    Pattern - The bytes to look for.

    PatternLength - Number of bytes in Pattern.

    MatchAddress - Receives the unique match, or zero on every failure.

Return Value:

    STATUS_SUCCESS - Exactly one eligible match was found and reported.

    STATUS_NOT_FOUND - The image parsed, but no section contains the
        pattern.

    STATUS_OBJECT_NAME_COLLISION - At least two eligible matches exist.

    STATUS_INVALID_IMAGE_PROTECT / STATUS_INVALID_IMAGE_FORMAT - The image
        headers did not parse.

--*/
{
    IMAGE_DOS_HEADER* DosHeader;
    IMAGE_NT_HEADERS64* NtHeaders;
    IMAGE_SECTION_HEADER* Section;
    PUCHAR Code;
    ULONG64 Base;
    ULONG64 FoundAddress;
    ULONG64 SectionTableOffset;
    ULONG SectionIndex;
    ULONG Offset;
    ULONG SectionLength;
    ULONG Match;

    PAGED_CODE();

    *MatchAddress = 0;

    if ((PatternLength == 0) || (Pattern == NULL) || (ImageSize == 0) ||
        (ImageBase == 0) || (ImageBase > (MAXULONG_PTR - ImageSize)))
    {
        return STATUS_INVALID_PARAMETER;
    }

    Base = ImageBase;
    FoundAddress = 0;

    //
    // Parse the image the way the loader laid it out in memory: DOS
    // header, NT headers, then the section table. Every offset is
    // validated against the module size the module list reported.
    //

    if (ImageSize < sizeof(IMAGE_NT_HEADERS64))
    {
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    DosHeader = (IMAGE_DOS_HEADER*)(ULONG_PTR)Base;

    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KmWarning("Image %p has no DOS signature\n", (PVOID)(ULONG_PTR)Base);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((DosHeader->e_lfanew < sizeof(IMAGE_DOS_HEADER)) ||
        ((ULONG)DosHeader->e_lfanew > (ImageSize - sizeof(IMAGE_NT_HEADERS64))))
    {
        KmWarning("Image %p has an out of bounds PE header offset\n",
            (PVOID)(ULONG_PTR)Base);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    NtHeaders = (IMAGE_NT_HEADERS64*)((PUCHAR)(ULONG_PTR)Base + DosHeader->e_lfanew);

    if ((NtHeaders->Signature != IMAGE_NT_SIGNATURE) ||
        (NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) ||
        (NtHeaders->FileHeader.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) ||
        (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC))
    {
        KmWarning("Image %p has no PE32+ signature\n", (PVOID)(ULONG_PTR)Base);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    if ((NtHeaders->FileHeader.NumberOfSections == 0) ||
        (NtHeaders->FileHeader.NumberOfSections > KM_MODULE_MAX_SECTIONS))
    {
        KmWarning("Image %p reports %u sections\n",
            (PVOID)(ULONG_PTR)Base, NtHeaders->FileHeader.NumberOfSections);
        return STATUS_INVALID_IMAGE_PROTECT;
    }

    //
    // IMAGE_FIRST_SECTION follows SizeOfOptionalHeader, not sizeof the NT
    // header structure. Validate that same offset with wide arithmetic
    // before constructing a pointer to the table.
    //

    SectionTableOffset = (ULONG64)(ULONG)DosHeader->e_lfanew +
        FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        NtHeaders->FileHeader.SizeOfOptionalHeader;

    if ((SectionTableOffset > ImageSize) ||
        (NtHeaders->FileHeader.NumberOfSections >
            ((ImageSize - SectionTableOffset) / sizeof(IMAGE_SECTION_HEADER))))
    {
        KmWarning("Image %p has an out of bounds section table\n",
            (PVOID)(ULONG_PTR)Base);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    Section = (IMAGE_SECTION_HEADER*)((PUCHAR)(ULONG_PTR)Base + SectionTableOffset);

    for (SectionIndex = 0;
         SectionIndex < NtHeaders->FileHeader.NumberOfSections;
         SectionIndex += 1)
    {
        //
        // Only sections the loader mapped readable and executable are
        // candidates: a pattern hit anywhere else would be data that
        // cannot be entered.
        //
        // Pageability is a naming convention, not a flag: the sections
        // the memory manager pages out are the ones whose names begin
        // with "PAGE" (and the "INIT" section is discarded after boot),
        // and they carry the same execute and read characteristics as
        // resident code. A match in one of them would be an address that
        // can be entered but not relied on to still be there at DIRQL,
        // so they are excluded outright.
        //

        if (((Section[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) == 0) ||
            ((Section[SectionIndex].Characteristics & IMAGE_SCN_MEM_READ) == 0) ||
            ((Section[SectionIndex].Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0))
        {
            continue;
        }

        if ((Section[SectionIndex].Name[0] == 'P') &&
            (Section[SectionIndex].Name[1] == 'A') &&
            (Section[SectionIndex].Name[2] == 'G') &&
            (Section[SectionIndex].Name[3] == 'E'))
        {
            continue;
        }

        if ((Section[SectionIndex].Name[0] == 'I') &&
            (Section[SectionIndex].Name[1] == 'N') &&
            (Section[SectionIndex].Name[2] == 'I') &&
            (Section[SectionIndex].Name[3] == 'T'))
        {
            continue;
        }

        SectionLength = (Section[SectionIndex].Misc.VirtualSize != 0) ?
            Section[SectionIndex].Misc.VirtualSize :
            Section[SectionIndex].SizeOfRawData;

        if ((Section[SectionIndex].VirtualAddress >= ImageSize) ||
            (SectionLength > (ImageSize - Section[SectionIndex].VirtualAddress)))
        {
            KmWarning("Image %p section %u runs past the image\n",
                (PVOID)(ULONG_PTR)Base, SectionIndex);
            return STATUS_INVALID_IMAGE_FORMAT;
        }

        if (SectionLength < PatternLength)
        {
            continue;
        }

        Code = (PUCHAR)(ULONG_PTR)Base + Section[SectionIndex].VirtualAddress;

        for (Offset = 0; Offset <= (SectionLength - PatternLength); Offset += 1)
        {
            Match = 0;

            while ((Match < PatternLength) &&
                   (Code[Offset + Match] == Pattern[Match]))
            {
                Match += 1;
            }

            if (Match == PatternLength)
            {
                if (FoundAddress != 0)
                {
                    KmError("Ambiguous pattern - First=%p Second=%p\n",
                        (PVOID)(ULONG_PTR)FoundAddress, &Code[Offset]);
                    return STATUS_OBJECT_NAME_COLLISION;
                }

                KmTrace("Pattern found at %p (section %u, offset 0x%X)\n",
                    &Code[Offset], SectionIndex, Offset);

                FoundAddress = (ULONG64)(ULONG_PTR)&Code[Offset];
            }
        }
    }

    if (FoundAddress != 0)
    {
        *MatchAddress = FoundAddress;
        return STATUS_SUCCESS;
    }

    KmError("Pattern not found in the executable sections of %p\n",
        (PVOID)(ULONG_PTR)Base);

    return STATUS_NOT_FOUND;
}

#pragma code_seg(pop)
