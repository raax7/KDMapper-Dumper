#include "Globals.h"
#include "NT.h"
#include "Utils.h"
#include <wchar.h>

#pragma warning(disable: 4244)

NTSTATUS DumpMemoryToDisk(
    _In_ const WCHAR* FileNamePrefix,
    _In_ PVOID BaseAddress,
    _In_ UINT64 Size)
{
    if (BaseAddress == NULL || Size == 0)
    {
        DBG("Attempted to dump memory with no base address or size!");
        return STATUS_INVALID_PARAMETER;
    }

    HANDLE             h_file;
    UNICODE_STRING     name;
    OBJECT_ATTRIBUTES  attr;
    IO_STATUS_BLOCK    status_block;
    LARGE_INTEGER      offset{ NULL };

    //
    // Get the current kernel time and use that as the filen name.
    //
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    //
    // Create the file name using the current time.
    //
    WCHAR FileName[260];
    swprintf(FileName, L"\\??\\C:\\%s_%lld.bin", FileNamePrefix, CurrentTime.QuadPart);

    //
    // Initialize the unicode string.
    //
    RtlInitUnicodeString(&name, FileName);
    InitializeObjectAttributes(&attr, &name,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL
    );

    NTSTATUS Status = ZwCreateFile(
        &h_file,
        GENERIC_WRITE,
        &attr,
        &status_block,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        NULL,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        NULL
    );
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to create file - 0x%X", Status);
        return Status;
    }

    Status = ZwWriteFile(
        h_file,
        NULL,
        NULL,
        NULL,
        &status_block,
        BaseAddress,
        Size,
        &offset,
        NULL
    );
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to write to file - 0x%X", Status);
    }

    ZwClose(h_file);
    return Status;
}