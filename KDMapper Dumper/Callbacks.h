#pragma once
#include <ntifs.h>

static BOOLEAN LoadImageCallbackRegistered = FALSE;

VOID ImageLoadCallback(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,
    _In_ PIMAGE_INFO ImageInfo);