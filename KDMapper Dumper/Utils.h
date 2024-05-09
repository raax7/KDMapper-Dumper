#pragma once
#include <ntifs.h>

extern "C" NTSTATUS NTSYSAPI MmCopyVirtualMemory(
    _In_ PEPROCESS SourceProcess,
    _In_ PVOID SourceAddress,
    _In_ PEPROCESS TargetProcess,
    _Out_ PVOID TargetAddress,
    _In_ SIZE_T BufferSize,
    _In_ KPROCESSOR_MODE PreviousMode,
    _Out_ PSIZE_T ReturnSize);

NTSTATUS DumpMemoryToDisk(
    _In_ const WCHAR* FileNamePrefix,
    _In_ PVOID BaseAddress,
    _In_ UINT64 Size);