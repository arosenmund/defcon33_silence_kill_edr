#pragma once
#define VADDR_TO_INDEX(va, shift) (((va) >> (shift)) & 0x1FF)
#define PAGE_PRESENT   0x1
#define LARGE_PAGE     0x80
