#include <Windows.h>
#include <stdio.h>
#include <tchar.h>


// 枚举资源类型
BOOL EnumTypesFunc(HMODULE hModule, LPTSTR lpType, LONG_PTR lParam);

// 枚举资源名称
BOOL EnumNamesFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, LONG_PTR lParam);

// 枚举资源语言
BOOL EnumLangsFunc(HMODULE hModule, LPTSTR lpType, LPTSTR lpName, WORD wLanguage, LONG_PTR lParam);


struct Resource {
	LPTSTR lpType;
	LPTSTR lpName;
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

	HANDLE hUpdate = BeginUpdateResource(Destination, FALSE);
	if (!hUpdate) {
		_tprintf(_T("[x] BeginUpdateResource Failed, Path: %s, Error: %#x\n"), Destination, GetLastError());

		delete[] Resources.List;

		return 0;
	}

	for (int i = 0; i < Resources.Count; i++) {

		if (!IS_INTRESOURCE(Resources.List[i].lpType)) {
			// _tprintf(_T("[!] Type: %s\n"), Resources.List[i].lpType);
			continue;
		}

		if (!IS_INTRESOURCE(Resources.List[i].lpName)) {
			// _tprintf(_T("[!] Name: %s\n"), Resources.List[i].lpName);
			continue;
		}

		//_tprintf(_T("[%d] Type: %u, Name: %u, Lang: %u\n"), i,
		//	(USHORT)Resources.List[i].lpType, (USHORT)Resources.List[i].lpName, Resources.List[i].wLanguage);

		BOOL Result = UpdateResource(
			hUpdate,
			Resources.List[i].lpType,
			Resources.List[i].lpName,
			Resources.List[i].wLanguage,
			NULL, 0
		);

		if (Result == FALSE) {
			_tprintf(_T("[x] UpdateResource Failed. Error: %#x\n"), GetLastError());
			continue;
		}
	}

	if (!EndUpdateResource(hUpdate, FALSE)) {
		_tprintf(_T("[x] EndUpdateResource Failed. Error: %#x\n"), GetLastError());

		delete[] Resources.List;

		return FALSE;
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

	Resources->List[Resources->Count] = Resource{
		lpType, lpName, wLanguage
	};
	Resources->Count += 1;

	return TRUE;
}
