#include "Callbacks.h"
#include "Globals.h"
#include "IATHook.h"
#include "NT.h"
#include "Utils.h"

typedef NTSTATUS(*PFN_ORIGINAL_IO_CONTROL)(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    );

PFN_ORIGINAL_IO_CONTROL  OriginalIOControl = NULL;

NTSTATUS hk_ControlIO(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;

    if (ControlCode != TARGET_IOCTL_CODE
        || Stack->Parameters.DeviceIoControl.InputBufferLength == 0)
        goto EXIT;

    PCOPY_MEMORY_BUFFER_INFO Buffer = (PCOPY_MEMORY_BUFFER_INFO)Stack->Parameters.SetFile.DeleteHandle;
    if (Buffer == NULL
        || Buffer->CaseNumber != TARGET_CASENUMBER)
        goto EXIT;

    //
    // credits: https://github.com/uefibootkit/kdmapper-dumper
    // The first check checks if the address is inside the kernel.
    // The second check is to avoid dumping the inline hook shellcode KDMapper writes.
    //
    if (virt_addr_t{ Buffer->Destination }.pml4_index <= 255
        || Buffer->Length < 0x100)
        goto EXIT;

    DBG("Dumping Memory! Source: 0x%p Destination: 0x%p Size: %d", Buffer->Source, Buffer->Destination, Buffer->Length);

    NTSTATUS Status = DumpMemoryToDisk(L"KDMapperDumper", (PVOID)((UINT64)Buffer->Source - 0x400), Buffer->Length + 0x400);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to dump memory - 0x%X", Status);
    }

    //
    // Get the PEPROCESS making the IOCTL request by getting the current thread and then the process.
    //
    ULONG ProcessId = IoGetRequestorProcessId(Irp);
    PEPROCESS SourceProcess = NULL;
    Status = PsLookupProcessByProcessId((HANDLE)ProcessId, &SourceProcess);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to get source process - 0x%X", Status);
        goto EXIT;
    }

    //
    // Attempt to dump the original driver with the PE header by attaching to the source process
    // and then going back 0x1000 bytes from the mapped driver.
    //
    PVOID Pool = ExAllocatePool2(POOL_FLAG_NON_PAGED, Buffer->Length + 0x1000, POOL_TAG2);
    if (Pool == NULL)
    {
        DBG("Failed to allocate pool buffer!");
        ObDereferenceObject(SourceProcess);
        goto EXIT;
    }

    SIZE_T ReturnSize = 0;
    Status = MmCopyVirtualMemory(
        SourceProcess,
        (PVOID)((UINT64)Buffer->Source - 0x1000),
        PsGetCurrentProcess(),
        Pool,
        Buffer->Length + 0x1000,
        KernelMode,
        &ReturnSize);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to copy memory - 0x%X", Status);
        ExFreePoolWithTag(Pool, POOL_TAG2);
        ObDereferenceObject(SourceProcess);
        goto EXIT;
    }

    ObDereferenceObject(SourceProcess);

    //
    // Dump the driver to disk.
    //
    Status = DumpMemoryToDisk(L"KDMapperDumper_PEHeader_UNFIXED", Pool, Buffer->Length + 0x1000);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to dump memory with unfixed PE header - 0x%X", Status);
    }

    //
    // Fix the PE header by looping through every section
    // and setting the PointerToRawData to VirtualAddress and the SizeOfRawData to VirtualSize.
    //
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Pool;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        DBG("Failed to fix PE header - Invalid DOS signature. You can most likely manually fix it still. Probably caused by different section alignment.");
        ExFreePoolWithTag(Pool, POOL_TAG2);
        goto EXIT;
    }

    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)Pool + DosHeader->e_lfanew);
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        DBG("Failed to fix PE header - Invalid NT signature. You can most likely manually fix it still. Probably caused by different section alignment.");
        ExFreePoolWithTag(Pool, POOL_TAG2);
        goto EXIT;
    }

    PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
    for (UINT32 i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        Section->PointerToRawData = Section->VirtualAddress;
        Section->SizeOfRawData = Section->Misc.VirtualSize;
        Section++;
    }

    //
    // Dump the fixed driver to disk.
    //
    Status = DumpMemoryToDisk(L"KDMapperDumper_PEHeader_FIXED", Pool, Buffer->Length + 0x1000);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to dump memory with fixed PE header - 0x%X", Status);
    }

EXIT:
    if (OriginalIOControl != NULL)
    {
        return OriginalIOControl(DeviceObject, Irp);
    }
    else
    {
        DBG("Attempted to call original IRP_MJ_DEVICE_CONTROL but it was NULL.");
        return STATUS_UNSUCCESSFUL;
    }
}

NTSTATUS hk_IoCreateDevice(
    PDRIVER_OBJECT  DriverObject,
    ULONG           DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE     DeviceType,
    ULONG           DeviceCharacteristics,
    BOOLEAN         Exclusive,
    PDEVICE_OBJECT* DeviceObject
)
{
    DBG("Swapping IRP_MJ_DEVICE_CONTROL.");

    OriginalIOControl = DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL];
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = hk_ControlIO;

    DBG("0x%p was swapped with 0x%p.", OriginalIOControl, hk_ControlIO);

    return IoCreateDevice(
        DriverObject,
        DeviceExtensionSize,
        DeviceName,
        DeviceType,
        DeviceCharacteristics,
        Exclusive,
        DeviceObject);
}

VOID ImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ProcessId);

    if (ImageInfo->SystemModeImage == FALSE)
        return;

    //
    // Copy the first 0x1000 bytes of the image to an allocated pool buffer.
    //
    PVOID ImageBase = ImageInfo->ImageBase;
    SIZE_T PoolSize = min(ImageInfo->ImageSize, 0x1000);

    PVOID ImageBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, PoolSize, POOL_TAG);
    if (ImageBuffer == NULL)
    {
        DBG("Failed to allocate pool buffer!");
        return;
    }

    RtlCopyMemory(ImageBuffer, ImageBase, PoolSize);

    //
    // Check the file header timestamp to see if it matches the timestamp of the KDMapper driver.
    //
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBuffer;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ExFreePoolWithTag(ImageBuffer, POOL_TAG);
        return;
    }

    DWORD Timestamp = *(PULONG)((PUCHAR)ImageBuffer + DosHeader->e_lfanew + 0x8);
    if (Timestamp != INTEL_LAN_DRIVER_TIMESTAMP)
    {
        ExFreePoolWithTag(ImageBuffer, POOL_TAG);
        return;
    }

    DBG("Found Intel LAN driver at: 0x%p", ImageBase);

    NTSTATUS Status = HookIATEntry(ImageBase, "ntoskrnl.exe", "IoCreateDevice", hk_IoCreateDevice);
    if (NT_SUCCESS(Status) == false)
    {
        DBG("Failed to hook IoCreateDevice() in Intel LAN Driver! - 0x%X", Status);
    }

    return;
}