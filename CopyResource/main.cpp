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


#define MAX_LENGTH 128

struct Resource {
	struct ResourceType {
		BOOL IsIntResource;
		union {
			LPTSTR lpType;
			TCHAR szType[MAX_LENGTH];
		};
	};

	struct ResourceName {
		BOOL IsIntResource;
		union {
			LPTSTR lpName;
			TCHAR szName[MAX_LENGTH];
		};
	};

	ResourceType Type;
	ResourceName Name;
	WORD wLanguage;
};

struct ResourceList {
	Resource* List;
	INT Max;
	INT Count;
};


int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 3) {
		_tprintf(_T("[x] Usage: CopyResource.exe [YourExe.exe] [Original.exe]\n"));
		return 0;
	}

	TCHAR* Destination = argv[1];
	TCHAR* Original = argv[2];

	HMODULE hModule = LoadLibraryEx(Original, NULL, LOAD_LIBRARY_AS_DATAFILE);
	if (!hModule) {
		_tprintf(_T("[x] LoadLibrary Failed, Path: %s, Error: %#x\n"), Original, GetLastError());
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

	HANDLE hUpdate = BeginUpdateResource(Destination, TRUE);
	if (!hUpdate) {
		_tprintf(_T("[x] BeginUpdateResource Failed, Path: %s, Error: %#x\n"), Destination, GetLastError());

		delete[] Resources.List;
		FreeLibrary(hModule);

		return 0;
	}

	for (int i = 0; i < Resources.Count; i++) {

		//
		// 调试输出
		//

		if (Resources.List[i].Type.IsIntResource) {
			_tprintf(_T("[+] Copying %d Resource, Type: %d, "), i, (INT)(ULONG_PTR)Resources.List[i].Type.lpType);
		}
		else {
			_tprintf(_T("[+] Copying %d Resource, Type: %s, "), i, Resources.List[i].Type.szType);
		}

		// 资源名称
		if (Resources.List[i].Name.IsIntResource) {
			_tprintf(_T("Name: %d\n"), (INT)(ULONG_PTR)Resources.List[i].Name.lpName);
		}
		else {
			_tprintf(_T("Name: %s\n"), Resources.List[i].Name.szName);
		}

		//
		// 查找资源
		//

		HRSRC hResource = FindResourceEx(
			hModule,
			Resources.List[i].Type.IsIntResource ?
			Resources.List[i].Type.lpType : Resources.List[i].Type.szType,
			Resources.List[i].Name.IsIntResource ?
			Resources.List[i].Name.lpName : Resources.List[i].Name.szName,
			Resources.List[i].wLanguage
		);

		if (hResource == NULL) {
			_tprintf(_T("[!] FindResource Failed, Error: %#x\n"), GetLastError());
			continue;
		}

		HGLOBAL hGlobal = LoadResource(hModule, hResource);
		if (hGlobal == NULL) {
			_tprintf(_T("[!] LoadResource Failed, Error: %#x\n"), GetLastError());
			continue;
		}

		LPVOID ResourceData = (LPVOID)LockResource(hGlobal);
		DWORD ResourceSize = SizeofResource(hModule, hResource);

		if (ResourceData == NULL || ResourceSize == 0) {
			_tprintf(_T("[!] ResourceData = 0x%p, ResourceSize = %d\n"), ResourceData, ResourceSize);
			continue;
		}

		//
		// 更新资源
		//

		BOOL Result = UpdateResource(
			hUpdate,
			Resources.List[i].Type.IsIntResource ?
			Resources.List[i].Type.lpType : Resources.List[i].Type.szType,
			Resources.List[i].Name.IsIntResource ?
			Resources.List[i].Name.lpName : Resources.List[i].Name.szName,
			Resources.List[i].wLanguage,
			ResourceData,
			ResourceSize
		);

		if (Result == FALSE) {
			_tprintf(_T("[x] UpdateResource Failed. Error: %#x\n"), GetLastError());

			EndUpdateResource(hUpdate, TRUE); // 放弃修改

			delete[] Resources.List;
			FreeLibrary(hModule);

			return 0;
		}
	}

	if (!EndUpdateResource(hUpdate, FALSE)) {
		_tprintf(_T("[x] EndUpdateResource Failed. Error: %#x\n"), GetLastError());

		delete[] Resources.List;
		FreeLibrary(hModule);

		return 0;
	}

	delete[] Resources.List;
	FreeLibrary(hModule);

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
		Resources->List[Resources->Count].Type.lpType = lpType;
	}
	else {
		Resources->List[Resources->Count].Type.IsIntResource = FALSE;
		_tcsncpy(Resources->List[Resources->Count].Type.szType, lpType, MAX_LENGTH);
	}

	// 资源名称
	if (IS_INTRESOURCE(lpName)) {
		Resources->List[Resources->Count].Name.IsIntResource = TRUE;
		Resources->List[Resources->Count].Name.lpName = lpName;
	}
	else {
		Resources->List[Resources->Count].Name.IsIntResource = FALSE;
		_tcsncpy(Resources->List[Resources->Count].Name.szName, lpName, MAX_LENGTH);
	}

	// 资源语言
	Resources->List[Resources->Count].wLanguage = wLanguage;

	Resources->Count += 1;

	return TRUE;
}
