#include <Windows.h>
#include <iostream>
#include <tchar.h>

#include <peconv.h> // include libPeConv header
#include "util.h"

BYTE* g_Payload = nullptr;
size_t g_PayloadSize = 0;

#define FUNC_OFFSET 0x31274
#define OPCODE_BLOCK_OFFSET 0xE85A8
#define DATA_STC 0xE86C8
#define OPCODE_OUT 0xE8ED0 
#define PASS_BUF 0x168ED0

BYTE** g_OpcodeBlockPtr = nullptr;
BYTE* g_OpcodeBlock = nullptr;

BYTE* g_OpcodeOut = nullptr;
BYTE* g_DataStc = nullptr;
BYTE** g_ValidPass = nullptr;

#define _TEST

// manually load the PE file using libPeConv
bool load_payload(LPCTSTR pe_path)
{
	if (g_Payload) {
		// already loaded
		std::cerr << "[!] The payload is already loaded!\n";
		return false;
	}
#ifdef LOAD_FROM_PATH
	//if the PE is dropped on the disk, you can load it from the file:
	g_Payload = peconv::load_pe_executable(pe_path, g_PayloadSize);
#else // load from memory buffer
	/*
	in this example the memory buffer is first loaded from the disk,
	but it can as well be fetch from resources, or a hardcoded buffer
	*/
	size_t bufsize = 0;
	BYTE* buf = peconv::load_file(pe_path, bufsize);
	if (!buf) {
		return false;
	}
	// if the file is NOT dropped on the disk, you can load it directly from a memory buffer:
	g_Payload = peconv::load_pe_executable(buf, bufsize, g_PayloadSize, nullptr);
	std::cout << "Loaded payload at base: " << std::hex << (ULONGLONG)g_Payload << std::endl;

	// at this point we can free the buffer with the raw payload:
	peconv::free_file(buf); buf = nullptr;
	
#endif
	if (!g_Payload) {
		return false;
	}

	// if the loaded PE needs to access resources, you may need to connect it to the PEB:
	peconv::set_main_module_in_peb((HMODULE)g_Payload);

	g_OpcodeBlockPtr = (BYTE**)((ULONG_PTR)g_Payload + OPCODE_BLOCK_OFFSET);
	g_OpcodeOut = (BYTE*)((ULONG_PTR)g_Payload + OPCODE_OUT);
	g_DataStc = (BYTE*)((ULONG_PTR)g_Payload + DATA_STC);
	g_ValidPass = (BYTE**)((ULONG_PTR)g_Payload + PASS_BUF);
	return true;
}

int process()
{
	if (!g_Payload) {
		std::cerr << "[!] The payload is not loaded!\n";
		return -1;
	}
	const ULONG_PTR func_va = (ULONG_PTR)g_Payload + FUNC_OFFSET;
	//the simplest prototype of the main fuction:
	int basic_main(void);
	auto new_main = reinterpret_cast<decltype(&basic_main)>(func_va);
	//std::cout << "Running func\n";
	//call the Entry Point of the manually loaded PE:
	int ret = new_main();
	return ret;
}

void fill_pass(BYTE* _opcode, char* p)
{
	size_t indxs[] = { 5, 4, 12, 11, 19, 18, 26, 25, 33, 32, 40, 39, 47, 46, 54, 53 };
	size_t count = sizeof(indxs) / sizeof(indxs[0]);


	if (p) {
		wchar_t pass[32] = { 0 };
		size_t len = strlen(p);
		for (size_t i = 0; i < 32 && i < len; i++) {
			pass[i] = p[i];
		}
		for (size_t i = 0; i < count; i++) {
			size_t indx = indxs[i];
			//printf("%d : %x : %x\n", indx, _opcode[indx], pass[i]);
			_opcode[indx] = pass[i];
		}
	}
}

int to_process(BYTE* buf, size_t buf_size, char* pass)
{
	DWORD* dwBuf = (DWORD*)buf;
	if (dwBuf[0] != 'BT4C') {
		std::cerr << "Not a Catbert file\n";
		return (-1);
	}
	DWORD dataSize = dwBuf[1];
	DWORD bytecodeOffset = dwBuf[2];
	DWORD bytecodeSize = dwBuf[3];
	g_OpcodeBlock = (BYTE*)(ULONGLONG)(bytecodeOffset + (ULONG_PTR)buf);
	*g_OpcodeBlockPtr = g_OpcodeBlock;

	fill_pass(g_OpcodeBlock, pass);
	return process();
}

bool brutforceCat2(BYTE* buf, size_t buf_size)
{
	char password[32] = { 0 };

	BYTE* processed = g_OpcodeOut + 0xC8;
	BYTE* encrypted = g_OpcodeOut + 0x90;
	int res = 0;
	size_t pos = 0;

	bool valFound = true;
	for (pos = 0; pos < 30 && valFound; pos++) {
		valFound = false;
		for (char val = 0x20; val < 0x7e; val++) {
			password[pos] = val;
			res = to_process(buf, buf_size, password);
			if (*g_ValidPass) {
				valFound = true;
				break;
			}
			if (*processed != encrypted[pos]) {
				std::cout << "pass[" << pos << "] = " << val << "\n";
				valFound = true;
				break;
			}
		}
	}
	if (valFound) {
		std::cout << "PASS: " << password << "\n";
	}
	return valFound;
}

bool bruteCat3Chunk(BYTE* buf, size_t buf_size, std::vector<char> &charset, char *password, char defVal, const size_t pos, bool breakOnFirst)
{
	if (pos >= 8) return false;

	const size_t chunkSize = 4;
	char foundChunk[chunkSize + 1] = { 0 };
	::memset(foundChunk, defVal, chunkSize);

	bool isDone = false;
	bool anyFound = false;
	BYTE* nextBlock = g_OpcodeOut + 0xE0;
	
	for (auto itr1 = charset.begin(); !isDone && itr1 != charset.end(); ++itr1) {
		for (auto itr2 = charset.begin(); !isDone && itr2 != charset.end(); ++itr2) {
			for (auto itr3 = charset.begin(); !isDone && itr3 != charset.end(); ++itr3) {
				for (auto itr4 = charset.begin(); !isDone && itr4 != charset.end(); ++itr4) {
					password[pos] = *itr1;
					password[pos + 1] = *itr2;
					password[pos + 2] = *itr3;
					password[pos + 3] = *itr4;

					to_process(buf, buf_size, password);
					if (*g_ValidPass) {
						std::cout << "VALID\n";
						isDone = true;
						anyFound = true;
						return true;
					}
					//
					if (*nextBlock == defVal) {
						//printf("Next: %x\n", (*nextBlock));
						::memcpy(foundChunk, password + pos, 4);
						std::cout << "PASS Chunk[" <<pos << "]: " << foundChunk << "\n";
						anyFound = true;
						
						if (breakOnFirst) {
							isDone = true;
							return true;
						}
						
					}
				}
			}
		}
	}
	::memcpy(password + pos, foundChunk, chunkSize);
	return anyFound;
}

bool brutforceCat3(BYTE* buf, size_t buf_size)
{
	char password[32] = { 0 };
	int res = 0;
	char defVal = ' ';
	std::vector<char> charset;

	for (char c = 'A'; c <= 'Z'; c++) {
		charset.push_back(c);
	}
	for (char c = 'a'; c <= 'z'; c++) {
		charset.push_back(c);
	}

	::memset(password, defVal, sizeof(password) - 1);
	size_t pos = 0;
	if (!bruteCat3Chunk(buf, buf_size, charset, password, defVal, pos, false)) {
		std::cout << "Failed!\n";
		return false;
	}
	std::cout << "---\n";
	pos = 4;
	if (!bruteCat3Chunk(buf, buf_size, charset, password, defVal, pos, false)) {
		return false;
	}
	std::cout << "PASS: " << password << "\n";
	return true;
}

bool brutforceCat1(BYTE* buf, size_t buf_size)
{
	BYTE* nextChar = g_OpcodeOut + 0xB0;
	char password[32] = { 0 };
	::memset(password, ' ', 30);

	for (size_t pos = 0; pos < 30; pos++) {
		to_process(buf, buf_size, password);
		if (*g_ValidPass) {
			std::cout << "PASS: " << password << "\n";
			return true;
		}
		std::cout << "pass[" << pos << "] = " << *nextChar << "\n";
		password[pos] = *nextChar;
	}
	return false;
}

#define PART3_BRUTE

int _tmain(int argc, LPTSTR argv[])
{
	const LPTSTR pe_path = "shell.pe";
	if (!load_payload(pe_path)) {
		std::cerr << "ERROR: Executable to load: " << pe_path << " not found!\n";
		return -1;
	}
	if (argc < 3) {
		std::cout << "Args: <filename> <type> [pass]\n";
		return 0;
	}
	int type = atoi(argv[2]);
	std::cout << "Selected type: " << type << "\n";
	char* password = argc >= 3 ? argv[3] : nullptr;

	size_t buf_size = 0;
	BYTE* buf = read_file(argv[1], buf_size);
	if (!buf) {
		std::cerr << "Failed to read the file!\n";
		return 1;
	}

	std::cout << "Read: " << buf_size << "\n";
	int res = 0;
	if (password) {
		char* password = argc >= 3 ? argv[3] : nullptr;
		res = to_process(buf, buf_size, password);
	}
	else {
		bool isOk = false;
		if (type == 0) {
			std::cerr << "No type selected!\n";
			return 0;
		}
		else if (type == 1) {
			std::cout << "Part1 brute\n";
			isOk = brutforceCat1(buf, buf_size);
		}
		else if (type == 2) {
			std::cout << "Part2 brute\n";
			isOk = brutforceCat2(buf, buf_size);
		}
		else if (type == 3) {
			std::cout << "Part3 brute\n";
			isOk = brutforceCat3(buf, buf_size);
		}
		if (!isOk) {
			std::cerr << "[!] Brutforce failed\n";
		}
	}
	std::cout << "Func finished.\n";
	printf("IsValid: %x\n", (*g_ValidPass));
#ifdef _TEST
	{
		const char* path = "data_out.bin";
		if (save_to_file(path, g_OpcodeOut, 0x200)) {
			std::cout << "Saved to: " << path << "\n";
		}
		else {
			std::cout << "Failed to save: " << path << "\n";
		}
	}
#endif
	return 0;
}