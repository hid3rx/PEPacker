#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>


// 枚举资源类型
BOOL EnumTypesFunc(HMODULE hModule, LPTSTR lpType, LONG_PTR lParam);


// 枚举资源名称
BOOL EnumNamesFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, LONG_PTR lParam);


// 枚举资源语言
BOOL EnumLangsFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, WORD wLanguage, LONG_PTR lParam);


#define MAX_LENGTH 32

struct Resource {
	struct {
		BOOL IsIntResource;
		union {
			USHORT uType;
			TCHAR lpType[MAX_LENGTH];
		};
	} Type;

	struct {
		BOOL IsIntResource;
		union {
			USHORT uName;
			TCHAR lpName[MAX_LENGTH];
		};
	} Name;

	WORD wLanguage;
};

struct ResourceList {
	Resource* List;
	INT Max;
	INT Count;
};


int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 2) {
		_tprintf(_T("[x] Usage: ClearResource.exe [YourExe.exe]\n"));
		return 0;
	}

	TCHAR* Destination = argv[1];

	HMODULE hModule = LoadLibraryEx(Destination, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule) {
		_tprintf(_T("[x] LoadLibrary Failed, Path: %s, Error: %#x\n"), Destination, GetLastError());
		return 0;
	}

	ResourceList Resources;
	Resources.List = new Resource[512];
	Resources.Count = 0;
	Resources.Max = 512;

	BOOL Result = EnumResourceTypes((HMODULE)hModule, (ENUMRESTYPEPROC)EnumTypesFunc, (LONG_PTR)&Resources);
	if (Result == FALSE) {
		_tprintf(_T("[x] EnumResourceTypes Failed. Error: %#x\n"), GetLastError());

		delete[] Resources.List;
		FreeLibrary(hModule);

		return 0;
	}

	FreeLibrary(hModule);

	for (int i = 0; i < Resources.Count; i++) {

		HANDLE hUpdate = BeginUpdateResource(Destination, FALSE);
		if (!hUpdate) {
			_tprintf(_T("[x] BeginUpdateResource Failed, Path: %s, Error: %#x\n"), Destination, GetLastError());

			delete[] Resources.List;

			return 0;
		}

		BOOL Result = UpdateResource(
			hUpdate,
			Resources.List[i].Type.IsIntResource ? 
				(LPTSTR)Resources.List[i].Type.uType : Resources.List[i].Type.lpType,
			Resources.List[i].Name.IsIntResource ? 
				(LPTSTR)Resources.List[i].Name.uName : Resources.List[i].Name.lpName,
			Resources.List[i].wLanguage,
			NULL, 0
		);

		if (Result == FALSE) {
			_tprintf(_T("[x] UpdateResource Failed. Error: %#x\n"), GetLastError());
			
			delete[] Resources.List;

			return 0;
		}

		if (!EndUpdateResource(hUpdate, FALSE)) {
			_tprintf(_T("[x] EndUpdateResource Failed. Error: %#x\n"), GetLastError());

			delete[] Resources.List;

			return 0;
		}
	}

	delete[] Resources.List;

	_tprintf(_T("[+] Success"));

	return 0;
}


BOOL EnumTypesFunc(HMODULE hModule, LPTSTR lpType, LONG_PTR lParam)
{
	return EnumResourceNames(hModule, lpType, (ENUMRESNAMEPROC)EnumNamesFunc, lParam);
}


BOOL EnumNamesFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, LONG_PTR lParam)
{
	return EnumResourceLanguages(hModule, lpType, lpName, (ENUMRESLANGPROC)EnumLangsFunc, lParam);
}


BOOL EnumLangsFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, WORD wLanguage, LONG_PTR lParam)
{
	ResourceList* Resources = (ResourceList*)lParam;

	if (Resources->Count >= Resources->Max)
		return FALSE;

	// 资源类型
	if (IS_INTRESOURCE(lpType)) {
		Resources->List[Resources->Count].Type.IsIntResource = TRUE;
		Resources->List[Resources->Count].Type.uType = (USHORT)lpType;
	}
	else {
		Resources->List[Resources->Count].Type.IsIntResource = FALSE;
		_tcsncpy(Resources->List[Resources->Count].Type.lpType, lpType, MAX_LENGTH);
	}

	// 资源名称
	if (IS_INTRESOURCE(lpName)) {
		Resources->List[Resources->Count].Name.IsIntResource = TRUE;
		Resources->List[Resources->Count].Name.uName = (USHORT)lpName;
	}
	else {
		Resources->List[Resources->Count].Name.IsIntResource = FALSE;
		_tcsncpy(Resources->List[Resources->Count].Name.lpName, lpName, MAX_LENGTH);
	}

	// 资源语言
	Resources->List[Resources->Count].wLanguage = wLanguage;

	Resources->Count += 1;

	return TRUE;
}
