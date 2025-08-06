#pragma once
#include <windows.h>

#define RTCORE64_DEVICE_PATH L"\\\\.\\RTCore64"

#define IOCTL_READ_PHYSICAL_MEMORY  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_PHYSICAL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Input/output structure (must match driver's expectations)
typedef struct _PHYSICAL_MEMORY_RW {
    ULONGLONG address;     // Physical address to read from
    DWORD     size;        // Size to read/write
    ULONGLONG buffer;      // User-mode buffer to read into or write from
} PHYSICAL_MEMORY_RW;
