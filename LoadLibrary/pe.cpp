#include "pe.h"

VOID LoadPEHeads(PBYTE peBuff, PPE ppe) {
	ppe->pDosHeader = (PIMAGE_DOS_HEADER)peBuff;
	ppe->pNtHeader = (PIMAGE_NT_HEADERS)(peBuff + ppe->pDosHeader->e_lfanew);
	ppe->pSectionHeaders = (PIMAGE_SECTION_HEADER)((PBYTE)ppe->pNtHeader + sizeof(IMAGE_NT_HEADERS));
	return VOID();
}

HMODULE myLoadLibrary(PCSTR pLibFileName) {
	HANDLE hFile = CreateFileA(pLibFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) return NULL;
	DWORD szFile = GetFileSize(hFile, 0);
	if (szFile == INVALID_FILE_SIZE) return NULL;
	PBYTE fBuff = (PBYTE)VirtualAlloc(NULL, szFile, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(!ReadFile(hFile, fBuff, szFile, &szFile, NULL)) return NULL;
	PE pe;
	LoadPEHeads(fBuff, &pe);
	PBYTE peBuff = (PBYTE)VirtualAlloc(NULL, pe.pNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	//复制PE头
	myMemCpy(peBuff, fBuff, pe.pNtHeader->OptionalHeader.SizeOfHeaders);
	//复制数据段并对齐
	for (DWORD i = 0; i < pe.pNtHeader->FileHeader.NumberOfSections; i++) 
		myMemCpy(peBuff + pe.pSectionHeaders[i].VirtualAddress, fBuff + pe.pSectionHeaders[i].PointerToRawData, pe.pSectionHeaders[i].SizeOfRawData);
	//基址重定位
	if (pe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
		PIMAGE_BASE_RELOCATION pIBR = (PIMAGE_BASE_RELOCATION)(peBuff + pe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		PWORD Array = NULL;
		do {
			Array = (PWORD)((PBYTE)pIBR + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD i = 0; i < (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i++) {
				switch ((Array[i] & 0xf000) >> 12) {
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*((PDWORD_PTR)(peBuff + pIBR->VirtualAddress + (Array[i] & 0xfff))) += (DWORD_PTR)peBuff - pe.pNtHeader->OptionalHeader.ImageBase;
					break;
				case IMAGE_REL_BASED_DIR64:
					*((PDWORD_PTR)(peBuff + pIBR->VirtualAddress + (Array[i] & 0xfff))) += (DWORD_PTR)peBuff - pe.pNtHeader->OptionalHeader.ImageBase;
					break;
				}
			}
			pIBR = PIMAGE_BASE_RELOCATION((PBYTE)pIBR + pIBR->SizeOfBlock);
		} while (pIBR->VirtualAddress);
	}
	//输入表地址更改
	PIMAGE_IMPORT_DESCRIPTOR pID = (PIMAGE_IMPORT_DESCRIPTOR)(peBuff + pe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_IMPORT_BY_NAME pIIBN = NULL;
	while (pID->Characteristics) {
		HMODULE hModule = GetModuleHandleA((PCSTR)peBuff + pID->Name);
		if (hModule == NULL)
			hModule = LoadLibraryA((PCSTR)peBuff + pID->Name);
		if (hModule == NULL)
			return NULL;
		PIMAGE_THUNK_DATA IAT = PIMAGE_THUNK_DATA(peBuff + pID->FirstThunk);
		while (IAT->u1.ForwarderString) {
			if (IAT->u1.Ordinal & IMAGE_ORDINAL_FLAG) 
				IAT->u1.Function = (DWORD_PTR)GetProcAddress(hModule, MAKEINTRESOURCEA(IAT->u1.Ordinal ^ IMAGE_ORDINAL_FLAG));
			else {
				pIIBN = PIMAGE_IMPORT_BY_NAME(peBuff + IAT->u1.AddressOfData);
				IAT->u1.Function = (DWORD_PTR)GetProcAddress(hModule, pIIBN->Name);
			}
			IAT++;
		}
		pID++;
	}
	//基址修改
	pe.pNtHeader->OptionalHeader.ImageBase = (DWORD_PTR)peBuff;
	//DllMain调用
	typedef BOOL (APIENTRY* DllMain)(HMODULE hMod, DWORD  ul_reason_for_call, LPVOID lpReserved);
	DllMain dllmain = (DllMain)(peBuff + pe.pNtHeader->OptionalHeader.AddressOfEntryPoint);
	dllmain((HMODULE)peBuff, DLL_PROCESS_ATTACH, NULL);
	return HMODULE(peBuff);
}

FARPROC myGetProcAddress(HMODULE hModule, PCSTR pProcName) {
	PBYTE peBuff = (PBYTE)hModule;
	PE pe;
	LoadPEHeads(peBuff, &pe);
	PIMAGE_EXPORT_DIRECTORY pED = (PIMAGE_EXPORT_DIRECTORY)(peBuff + pe.pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD arrayFunctions = (PDWORD)(peBuff + pED->AddressOfFunctions);
	PWORD arrayNameOrdinals = (PWORD)(peBuff + pED->AddressOfNameOrdinals);
	PDWORD arrayNames = (PDWORD)(peBuff + pED->AddressOfNames);
	for (DWORD i = 0; i < pED->NumberOfNames; i++) {
		if (myStrEqu((PCSTR)(peBuff + arrayNames[i]), pProcName))
			return (FARPROC)(peBuff + arrayFunctions[arrayNameOrdinals[i]]);
	}
	return NULL;
}

VOID myMemCpy(PVOID _dst, const PVOID _src, DWORD _size) {
	PBYTE dst = (PBYTE)_dst;
	PBYTE src = (PBYTE)_src;
	for (DWORD i = 0; i < _size; i++)
		dst[i] = src[i];
	return VOID();
}

VOID myZeroMemSet(PVOID _dst, DWORD _size) {
	PBYTE dst = (PBYTE)_dst;
	for (DWORD i = 0; i < _size; i++)
		dst[i] = 0;
	return VOID();
}

BOOL myStrEqu(PCSTR _str1, PCSTR _str2) {
	INT i = 0;
	for (; i < MAX_PATH; i++) {
		if (_str1[i] != _str2[i])
			return FALSE;
		if (_str1[i] == 0 || _str2[i] == 0)
			break;
	}
	if (_str1[i] == _str2[i])
		return TRUE;
	return FALSE;
}
