#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gzip.h>
#include <cryptopp/base64.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>


#pragma warning(disable: 6011)

#define SECTION_NAME "UPX"
#define AES_BLOCK_SIZE 16

/*
* align必须是2的次方数，即0x1000这样末尾是0的数
*/
#define ALIGN(x, align) ((x+align-1)&~(align-1))


BYTE* ReadPeFile(TCHAR* PePath, DWORD* PeSize);
BYTE* EncryptData(BYTE* Data, INT Length, INT* OutputLength);
BOOL PackPE(TCHAR* StubPath, TCHAR* PackedPath, PVOID SectionData, DWORD SectionSize);


int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 2) {
		_tprintf(_T("[x] Usage: PEPacker.exe C:\\Path\\To\\File.exe\n"));
		return 0;
	}

	//
	// 读取需要加壳的PE文件
	//

	TCHAR* PePath = argv[1];

	DWORD PeSize;
	BYTE* PeAddress = ReadPeFile(PePath, &PeSize);

	if (PeAddress == NULL) {
		return -1;
	}

	_tprintf(_T("[+] Raw File Size: %#x\n"), PeSize);

	//
	// 加密文件
	//

	INT EncryptedSize = 0;
	BYTE* EncryptedData = EncryptData(PeAddress, PeSize, &EncryptedSize);

	free(PeAddress);

	if (EncryptedData == NULL) {
		return -1;
	}

	_tprintf(_T("[+] Encrypted Data Size: %#x\n"), EncryptedSize);

	_tprintf(_T("[+] Compression Ratio: %.2f\n"), (FLOAT)EncryptedSize / PeSize);

	//
	// 开始加壳
	//

	PVOID SectionData = EncryptedData;
	DWORD SectionSize = (DWORD)EncryptedSize;

	TCHAR* StubPath = (TCHAR*)_T("PEStub.exe");
	TCHAR* PackedPath = (TCHAR*)_T("Packed.exe");

	if (PackPE(StubPath, PackedPath, SectionData, SectionSize) == FALSE) {
		_tprintf(_T("[x] Failed to Packet PE File.\n"));
		free(EncryptedData);
		return -1;
	}

	_tprintf(_T("[+] Success.\n"));

	free(EncryptedData);

	return 0;
}


BYTE* ReadPeFile(TCHAR* PePath, DWORD* PeSize)
{
	HANDLE hFile = CreateFile(PePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateFile Failed, Path: %s. Error: %#x\n"), PePath, GetLastError());
		return NULL;
	}

	*PeSize = GetFileSize(hFile, NULL);
	BYTE* PeAddress = (BYTE*)malloc(*PeSize);
	if (PeAddress == NULL) {
		_tprintf(_T("[x] Malloc Failed, Size: %#x. Error: %#x\n"), *PeSize, GetLastError());
		CloseHandle(hFile);
		return NULL;
	}

	DWORD nBytesRead = 0;
	if (ReadFile(hFile, PeAddress, *PeSize, &nBytesRead, NULL) == FALSE) {
		_tprintf(_T("[x] ReadFile Failed, Path: %s. Error: %#x\n"), PePath, GetLastError());
		CloseHandle(hFile);
		return NULL;
	}

	CloseHandle(hFile);

	return PeAddress;
}


BYTE* EncryptData(BYTE* Data, INT Length, INT* OutputLength)
{
	std::string Key;
	std::string IV = "0123456789ABCDEF";

	try {
		CryptoPP::FileSource fs("LICENSE.txt", true,
			new CryptoPP::HexDecoder(
				new CryptoPP::StringSink(Key)));
	}
	catch (CryptoPP::Exception& e) {
		_tprintf(_T("[x] Read Key Error: %hs\n"), e.what());
		return NULL;
	}

	if (Key.length() != 16 && Key.length() != 24 && Key.length() != 32) {
		_tprintf(_T("[x] Wrong Key Length\n"));
		return NULL;
	}

	std::string Input((CHAR*)Data, Length);
	CryptoPP::StringSource Source(Input, false);

	std::string Output;
	CryptoPP::StringSink Sink(Output);

	try {
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption Encryption;
		Encryption.SetKeyWithIV((byte*)Key.c_str(), Key.length(), (byte*)IV.c_str());
		CryptoPP::StreamTransformationFilter Encryptor(Encryption);

		CryptoPP::Gzip Gzip(nullptr, CryptoPP::Gzip::MAX_DEFLATE_LEVEL);
		CryptoPP::Base64Encoder Base64Encoder(nullptr, false);

		Source.Attach(new CryptoPP::Redirector(Gzip));
		Gzip.Attach(new CryptoPP::Redirector(Encryptor));
		Encryptor.Attach(new CryptoPP::Redirector(Base64Encoder));
		Base64Encoder.Attach(new CryptoPP::Redirector(Sink));

		Source.PumpAll();
	}
	catch (CryptoPP::Exception& e) {
		_tprintf(_T("[x] CryptoPP Encrypt Error: %hs\n"), e.what());
		return NULL;
	}

	INT OL = (INT)Output.length();
	BYTE* EncryptedData = (BYTE*)malloc(OL);
	if (EncryptedData == NULL) {
		_tprintf(_T("[x] Malloc Failed, Size: %#x. Error: %#x\n"), OL, GetLastError());
		return NULL;
	}
	memcpy(EncryptedData, Output.c_str(), OL);

	*OutputLength = OL;

	return EncryptedData;
}


BOOL PackPE(TCHAR* StubPath, TCHAR* PackedPath, PVOID SectionData, DWORD SectionSize)
{
	// 打开Stub文件
	HANDLE hStubFile = CreateFile(StubPath,
		GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hStubFile == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateFile Failed, Path: %s. Error: %#x\n"), StubPath, GetLastError());
		return FALSE;
	}

	DWORD dwFileSize = GetFileSize(hStubFile, NULL);

	/*
	* 计算文件新大小，大小需要与 0x200 对齐，对齐值一般是固定不变的，所以就提前写上了
	* 如有变动，按 NtHeaders->OptionalHeader.FileAlignment 的值修改
	*/
	DWORD dwNewFileSize = dwFileSize + ALIGN(SectionSize, 0x200);

	// 创建Packed文件
	HANDLE hPackedFile = CreateFile(PackedPath,
		GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hStubFile == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateFile Failed, Path: %s. Error: %#x\n"), StubPath, GetLastError());
		CloseHandle(hStubFile);
		return FALSE;
	}

	HANDLE hFileMapping = CreateFileMapping(hPackedFile, NULL, PAGE_READWRITE, 0, dwNewFileSize, NULL);
	if (hFileMapping == NULL) {
		_tprintf(_T("[x] CreateFileMapping Failed. Error: %#x\n"), GetLastError());
		CloseHandle(hPackedFile);
		CloseHandle(hStubFile);
		return FALSE;
	}

	PBYTE PeAddress = (PBYTE)MapViewOfFile(hFileMapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, dwNewFileSize);
	if (PeAddress == NULL) {
		_tprintf(_T("[x] MapViewOfFile Failed. Error: %#x\n"), GetLastError());
		CloseHandle(hFileMapping);
		CloseHandle(hPackedFile);
		CloseHandle(hStubFile);
		return FALSE;
	}

	// 复制Stub文件内容到Packed文件中
	DWORD nBytesRead = 0;
	if (ReadFile(hStubFile, PeAddress, dwFileSize, &nBytesRead, NULL) == FALSE) {
		_tprintf(_T("[x] ReadFile Failed, Path: %s. Error: %#x\n"), StubPath, GetLastError());
		UnmapViewOfFile(PeAddress);
		CloseHandle(hFileMapping);
		CloseHandle(hPackedFile);
		CloseHandle(hStubFile);
		return NULL;
	}

	CloseHandle(hStubFile);

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)PeAddress;
	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)PeAddress + DosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER SectionHeaders = (PIMAGE_SECTION_HEADER)((ULONG_PTR)NtHeaders + sizeof(IMAGE_NT_HEADERS));

	// 判断是否已经存在加壳段节
	for (int i = 0; i <= NtHeaders->FileHeader.NumberOfSections; i++) {
		if (strcmp((CHAR*)SectionHeaders[i].Name, SECTION_NAME) == 0) {
			_tprintf(_T("[x] Section Name Conflict Found: %hs.\n"), SECTION_NAME);
			UnmapViewOfFile(PeAddress);
			CloseHandle(hFileMapping);
			CloseHandle(hPackedFile);
			return FALSE;
		}
	}

	// 判断空隙是否足够装下新的段节
	SIZE_T AvailableSpace = (ULONG_PTR)PeAddress + SectionHeaders[0].PointerToRawData
		- (ULONG_PTR)&SectionHeaders[NtHeaders->FileHeader.NumberOfSections];
	if (AvailableSpace < sizeof(IMAGE_SECTION_HEADER)) {
		_tprintf(_T("[x] Remaining Space Is Not Enough To Add New Section.\n"));
		UnmapViewOfFile(PeAddress);
		CloseHandle(hFileMapping);
		CloseHandle(hPackedFile);
		return FALSE;
	}

	// 获取对齐值
	DWORD SectionAlignment = NtHeaders->OptionalHeader.SectionAlignment;
	DWORD FileAlignment = NtHeaders->OptionalHeader.FileAlignment;

	PIMAGE_SECTION_HEADER LastSection = &SectionHeaders[NtHeaders->FileHeader.NumberOfSections - 1];
	PIMAGE_SECTION_HEADER NewSection = &SectionHeaders[NtHeaders->FileHeader.NumberOfSections];

	// 新增段节
	memset(NewSection, 0, sizeof(IMAGE_SECTION_HEADER));
	memcpy(NewSection->Name, SECTION_NAME, min(sizeof(SECTION_NAME), 8));
	NewSection->Misc.VirtualSize = SectionSize;
	DWORD VirtualAddress = LastSection->VirtualAddress + LastSection->Misc.VirtualSize;
	NewSection->VirtualAddress = ALIGN(VirtualAddress, SectionAlignment);
	NewSection->SizeOfRawData = ALIGN(SectionSize, FileAlignment);
	DWORD PointerToRawData = LastSection->PointerToRawData + LastSection->SizeOfRawData;
	NewSection->PointerToRawData = PointerToRawData;
	NewSection->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;
	NtHeaders->FileHeader.NumberOfSections += 1;
	NtHeaders->OptionalHeader.SizeOfImage =
		ALIGN(NtHeaders->OptionalHeader.SizeOfImage + SectionSize, SectionAlignment);
	memcpy((BYTE*)PeAddress + NewSection->PointerToRawData, SectionData, SectionSize);

	// 释放资源
	UnmapViewOfFile(PeAddress);
	CloseHandle(hFileMapping);
	CloseHandle(hPackedFile);

	return TRUE;
}
