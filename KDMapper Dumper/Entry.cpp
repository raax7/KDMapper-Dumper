#include "Callbacks.h"
#include "Globals.h"
#include <ntifs.h>

extern "C" VOID Unload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (LoadImageCallbackRegistered)
    {
        PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
        LoadImageCallbackRegistered = FALSE;
    }

    DBG("Driver unloaded.");
}

extern "C" NTSTATUS DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status;
    DriverObject->DriverUnload = Unload;

    Status = PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to set image load notify routine - 0x%X.", Status);
        return Status;
    }
    LoadImageCallbackRegistered = TRUE;

    DBG("Driver loaded.");

    return STATUS_SUCCESS;
}