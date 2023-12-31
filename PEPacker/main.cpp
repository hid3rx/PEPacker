#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/gzip.h>
#include <cryptopp/base32.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>


#define RESOURCE_ID 1000
#define RESOURCE_MAX_SIZE 0x10000
#define AES_BLOCK_SIZE 16


// 读取PE文件
BYTE* ReadPeFile(TCHAR* PePath, DWORD* PeSize);


// 加密数据
BYTE* EncryptData(BYTE* Data, INT Length, INT* OutputLength);


// 更新PE资源
BOOL UpdatePEResource(TCHAR* StubPath, TCHAR* PackedPath, PBYTE EncrtyptedData, DWORD EncrtyptedSize);


int _tmain(int argc, TCHAR* argv[])
{
	if (argc != 3) {
		_tprintf(_T("[x] Usage: PEPacker.exe [PEStub.exe] [OtherPE.exe]\n"));
		return 0;
	}

	TCHAR* StubPath = argv[1];
	TCHAR* PePath = argv[2];

	TCHAR PackedPath[MAX_PATH];

	// 获取原始文件名
	TCHAR FileName[MAX_PATH];
	_tsplitpath(PePath, NULL, NULL, FileName, NULL);

	// 生成打包后的PE文件名
	_stprintf(PackedPath, _T("%s_packed.exe"), FileName);

	//
	// 读取需要加壳的PE文件
	//

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

	if (UpdatePEResource(StubPath, PackedPath, EncryptedData, EncryptedSize) == FALSE) {
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
		_tprintf(_T("[x] malloc Failed, Size: %#x. Error: %#x\n"), *PeSize, GetLastError());
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
		CryptoPP::Base32Encoder Base32Encoder(nullptr, false);

		Source.Attach(new CryptoPP::Redirector(Gzip));
		Gzip.Attach(new CryptoPP::Redirector(Encryptor));
		Encryptor.Attach(new CryptoPP::Redirector(Base32Encoder));
		Base32Encoder.Attach(new CryptoPP::Redirector(Sink));

		Source.PumpAll();
	}
	catch (CryptoPP::Exception& e) {
		_tprintf(_T("[x] CryptoPP Encrypt Error: %hs\n"), e.what());
		return NULL;
	}

	INT OL = (INT)Output.length();
	BYTE* EncryptedData = (BYTE*)malloc(OL);
	if (EncryptedData == NULL) {
		_tprintf(_T("[x] malloc Failed, Size: %#x. Error: %#x\n"), OL, GetLastError());
		return NULL;
	}
	memcpy(EncryptedData, Output.c_str(), OL);

	*OutputLength = OL;

	return EncryptedData;
}


BOOL UpdatePEResource(TCHAR* StubPath, TCHAR* PackedPath, PBYTE EncryptedData, DWORD EncryptedSize)
{
	if (CopyFile(StubPath, PackedPath, FALSE) == FALSE) {
		_tprintf(_T("[x] CopyFile Failed, StubPath: %s, PackedPath: %s. Error: %#x\n"),
			StubPath, PackedPath, GetLastError());
		return FALSE;
	}

	HANDLE hUpdate = BeginUpdateResource(PackedPath, FALSE);
	if (hUpdate == NULL) {
		printf("[x] BeginUpdateResource Failed. Error: %#x\n", GetLastError());
		return FALSE;
	}

	DWORD BlockNumbers = EncryptedSize / RESOURCE_MAX_SIZE;
	for (int i = 0; i < BlockNumbers; i++) {

		PBYTE ResourceData = EncryptedData + i * RESOURCE_MAX_SIZE;
		DWORD ResourceSize = RESOURCE_MAX_SIZE;

		BOOL Result = UpdateResource(hUpdate, _T("PACKER"), MAKEINTRESOURCE(RESOURCE_ID + i),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ResourceData, ResourceSize);
		if (Result == FALSE) {
			printf("[x] UpdateResource Failed. Error: %#x\n", GetLastError());
			EndUpdateResource(hUpdate, TRUE);
			return FALSE;
		}
	}

	DWORD RemainderSize = EncryptedSize % RESOURCE_MAX_SIZE;
	if (RemainderSize != 0) {

		PBYTE ResourceData = EncryptedData + BlockNumbers * RESOURCE_MAX_SIZE;
		DWORD ResourceSize = RemainderSize;

		BOOL Result = UpdateResource(hUpdate, _T("PACKER"), MAKEINTRESOURCE(RESOURCE_ID + BlockNumbers),
			MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), ResourceData, ResourceSize);
		if (Result == FALSE) {
			printf("[x] UpdateResource Failed. Error: %#x\n", GetLastError());
			EndUpdateResource(hUpdate, TRUE);
			return FALSE;
		}
	}

	if (!EndUpdateResource(hUpdate, FALSE)) {
		printf("[x] EndUpdateResource Failed. Error: %#x\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
