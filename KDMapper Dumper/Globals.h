#pragma once
#include <ntifs.h>

#pragma warning(disable: 4201)

#define INTEL_LAN_DRIVER_TIMESTAMP 0x5284EAC3
#define TARGET_IOCTL_CODE 0x80862007
#define TARGET_CASENUMBER 0x33

typedef unsigned long long uint64_t;

// credits: https://github.com/uefibootkit/kdmapper-dumper
typedef struct _COPY_MEMORY_BUFFER_INFO
{
    uint64_t CaseNumber;
    uint64_t Reserved;
    PVOID Source;
    PVOID Destination;
    uint64_t Length;
}COPY_MEMORY_BUFFER_INFO, * PCOPY_MEMORY_BUFFER_INFO;

// credits: https://github.com/uefibootkit/kdmapper-dumper
typedef union _virt_addr_t
{
    PVOID Value;
    struct
    {
        ULONG64 offset : 12;
        ULONG64 pt_index : 9;
        ULONG64 pd_index : 9;
        ULONG64 pdpt_index : 9;
        ULONG64 pml4_index : 9;
        ULONG64 reserved : 16;
    };
} virt_addr_t, * pvirt_addr_t;

#define POOL_TAG 'KDM '
#define POOL_TAG2 'KDM2'

#define DBG(Message, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[KDMapper Dumper] " __FUNCTION__ "() - " Message "\n", __VA_ARGS__)