#define Author xiaoice
#include "pe.h"
INT main(VOID) {
	HMODULE hMod = myLoadLibrary("..\\x64\\Release\\testDll.dll"); //64位
	//HMODULE hMod = myLoadLibrary("..\\Release\\testDll.dll"); //32位
	_Add Add = (_Add)myGetProcAddress(hMod, "Add");
	printf("%d\n", Add(1, 2));
	return 0;
}




//INT main(VOID) { //系统函数测试
//	HMODULE hMod = LoadLibraryA("..\\x64\\Release\\testDll.dll");
//	_Add Add = (_Add)GetProcAddress(hMod, "Add");
//	printf("%d\n", Add(1, 2));
//	return 0;
//}