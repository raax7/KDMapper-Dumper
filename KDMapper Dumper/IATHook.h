#pragma once
#include <ntifs.h>

PVOID FindIATEntry(
    _In_ PVOID ImageBase,
    _In_ PCSTR ImportModuleName,
    _In_ PCSTR ImportFunctionName);

NTSTATUS HookIATEntry(
    _In_ PVOID ImageBase,
    _In_ PCSTR ImportModuleName,
    _In_ PCSTR ImportFunctionName,
    _In_ PVOID NewFunction);