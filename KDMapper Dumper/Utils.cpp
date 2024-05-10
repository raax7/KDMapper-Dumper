#include "Globals.h"
#include "NT.h"
#include "Utils.h"
#include <wchar.h>

#pragma warning(disable: 4244)

// credit: https://github.com/uefibootkit/kdmapper-dumper
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

    HANDLE File;
    UNICODE_STRING FileNameUnicode;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK StatusBlock;
    LARGE_INTEGER Offset{ NULL };

    //
    // Get the current system time and use that in the file name.
    //
    LARGE_INTEGER CurrentTime;
    KeQuerySystemTime(&CurrentTime);

    WCHAR FileName[260];
    swprintf(FileName, L"\\??\\C:\\%s_%lld.bin", FileNamePrefix, CurrentTime.QuadPart);

    //
    // Initialize the unicode string.
    //
    RtlInitUnicodeString(&FileNameUnicode, FileName);
    InitializeObjectAttributes(&Attributes, &FileNameUnicode,
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        NULL, NULL
    );

    NTSTATUS Status = ZwCreateFile(
        &File,
        GENERIC_WRITE,
        &Attributes,
        &StatusBlock,
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
        File,
        NULL,
        NULL,
        NULL,
        &StatusBlock,
        BaseAddress,
        Size,
        &Offset,
        NULL
    );
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to write to file - 0x%X", Status);
    }

    ZwClose(File);
    return Status;
}