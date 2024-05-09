#include "Globals.h"
#include "IATHook.h"
#include "NT.h"

PVOID FindIATEntry(
    _In_ PVOID ImageBase,
    _In_ PCSTR ImportModuleName,
    _In_ PCSTR ImportFunctionName)
{
    if (ImageBase == NULL)
    {
        DBG("ImageBase is NULL.");
        return NULL;
    }

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DBG("Invalid DOS signature.");
        return NULL;
    }
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)ImageBase + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("Invalid NT signature.");
        return NULL;
    }

    PIMAGE_DATA_DIRECTORY ImportDirectory = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (ImportDirectory->Size == 0)
    {
        DBG("Import directory is empty.");
        return NULL;
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)ImageBase + ImportDirectory->VirtualAddress);
    while (ImportDescriptor->Name != 0)
    {
        PSTR ModuleName = (PSTR)((ULONG_PTR)ImageBase + ImportDescriptor->Name);
        DBG("ModuleName: %s", ModuleName);

        if (_stricmp(ModuleName, ImportModuleName) == 0)
        {
            DBG("Module found!");
            break;
        }

        ImportDescriptor++;
    }

    if (ImportDescriptor->Name == 0)
    {
        DBG("Failed! Module not found.");
        return NULL;
    }

    PIMAGE_THUNK_DATA OriginalFirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)ImageBase + ImportDescriptor->OriginalFirstThunk);
    PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)ImageBase + ImportDescriptor->FirstThunk);
    while (OriginalFirstThunk->u1.AddressOfData != 0)
    {
        PIMAGE_IMPORT_BY_NAME ImportByName = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)ImageBase + OriginalFirstThunk->u1.AddressOfData);
        DBG("ImportByName: %s", ImportByName->Name);

        if (_stricmp((PCSTR)ImportByName->Name, ImportFunctionName) == 0)
        {
            DBG("Function found!");
            return &FirstThunk->u1.Function;
        }

        OriginalFirstThunk++;
        FirstThunk++;
    }

    DBG("Function not found.");
    return NULL;
}

NTSTATUS HookIATEntry(
    _In_ PVOID ImageBase,
    _In_ PCSTR ImportModuleName,
    _In_ PCSTR ImportFunctionName,
    _In_ PVOID NewFunction)
{
    NTSTATUS Status = STATUS_SUCCESS;

    if (NewFunction == NULL)
    {
        DBG("You must pass in a NewFunction address.");
        Status = STATUS_INVALID_PARAMETER;
        goto EXIT;
    }

    PVOID IATEntry = FindIATEntry(ImageBase, ImportModuleName, ImportFunctionName);
    if (IATEntry == NULL)
    {
        DBG("IAT entry not found.");
        Status = STATUS_NOT_FOUND;
        goto EXIT;
    }

    DBG("Hooking IAT entry for %s!%s at: 0x%p", ImportModuleName, ImportFunctionName, IATEntry);

    //
    // Create an MDL for the IAT entry.
    //
    PMDL Mdl = IoAllocateMdl(IATEntry, sizeof(PVOID), FALSE, FALSE, NULL);
    if (Mdl == NULL)
    {
        DBG("IoAllocateMdl() failed.");
        Status = STATUS_MEMORY_NOT_ALLOCATED;
        goto EXIT;
    }

    //
    // Lock the pages in RAM so it doesn't get paged out.
    //
    MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

    //
    // Create a new mapping for the memory.
    //
    PVOID MdlMapping = MmMapLockedPagesSpecifyCache(
        Mdl,
        KernelMode,
        MmNonCached,
        NULL,
        0,
        NormalPagePriority);
    if (MdlMapping == NULL)
    {
        DBG("MmMapLockedPagesSpecifyCache() failed.");
        Status = STATUS_INVALID_PARAMETER;
        goto EXIT_UNLOCKPAGES;
    }

    //
    // Set the page protection to allow writing.
    //
    Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("MmProtectMdlSystemAddress() failed.");
        Status = STATUS_INVALID_PARAMETER_1;
        goto EXIT_UNMAP;
    }

    //
    // Set the IAT Entry to the new function using the MDL mapping.
    //
    *(PVOID*)MdlMapping = NewFunction;

    //
    // Flush the instruction cache.
    //
    KeInvalidateAllCaches();

EXIT_UNMAP:
    MmUnmapLockedPages(MdlMapping, Mdl);
EXIT_UNLOCKPAGES:
    MmUnlockPages(Mdl);
    IoFreeMdl(Mdl);
EXIT:
    return Status;
}