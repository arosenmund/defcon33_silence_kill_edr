
#pragma once
#include <windows.h>
#include <cstdint>

HANDLE OpenDriver();
bool ReadPhys(HANDLE hDriver, uint64_t address, void* buffer, size_t size);
