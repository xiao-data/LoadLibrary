#pragma once
#include <Windows.h>
#include <stdio.h>
typedef INT(WINAPI* _Add)(INT x, INT y);
typedef struct PE_ {
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pSectionHeaders;
}PE, * PPE;
VOID LoadPEHeads(PBYTE peBuff, PPE ppe);
HMODULE myLoadLibrary(PCSTR pLibFileName);
FARPROC myGetProcAddress(HMODULE hModule, PCSTR pProcName);
VOID myMemCpy(PVOID _dst, const PVOID _src, DWORD _size);
VOID myZeroMemSet(PVOID _dst, DWORD _size);
INT myStrEqu(PCSTR str1, PCSTR str2);