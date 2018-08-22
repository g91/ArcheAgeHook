#include "StdAfx.h"
#include "Utils.h"

BYTE jmp[6] = { 0xe9,0x00, 0x00, 0x00, 0x00 ,0xc3 };
DWORD pPrevious;

DWORD Utils::HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);
	ReadProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0);
	DWORD dwCalc = ((DWORD)lpFunction - dwAddr - 5);
	VirtualProtect((void*)dwAddr, 6, PAGE_EXECUTE_READWRITE, &pPrevious);
	memcpy(&jmp[1], &dwCalc, 4);
	WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, jmp, 6, 0);
	VirtualProtect((void*)dwAddr, 6, pPrevious, &pPrevious);
	FlushInstructionCache(GetCurrentProcess(), 0, 0);
	return dwAddr;
}

BOOL Utils::UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup)
{
	DWORD dwAddr = (DWORD)GetProcAddress(GetModuleHandle(lpModule), lpFuncName);

	if (WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwAddr, lpBackup, 6, 0))
		return TRUE;
	FlushInstructionCache(GetCurrentProcess(), 0, 0);

	return FALSE;
}


void Utils::HexDump(void *ptr, int buflen) 
{
	unsigned char *buf = (unsigned char*)ptr;
	int i, j;
	for (i = 0; i < buflen; i += 16) 
	{
		Logger2(lINFO, "AGH", "%06x: ", i);
		for (j = 0; j < 16; j++)
			if ((i + j) < buflen)
				Logger2(lINFO, "AGH", "%02x ", buf[i+j]);
			else
				Logger2(lINFO, "AGH", "   ");
		Logger2(lINFO, "AGH", " ");
		for (j = 0; j < 16; j++) 
			if ((i + j) < buflen)
				Logger2(lINFO, "AGH", "%c", isprint(buf[i + j]) ? buf[i + j] : '.');
		Logger2(lINFO, "AGH", "\n");
	}
}


// standard unix ELF hash
// adapted to work caseinsensitive and ignore unicode
DWORD Utils::Str2Hash(char *str, int length, int casesensitive, int incr)
{
	DWORD dwHash;
	// determine length of str if not given
	if( length==0 ) {
		while( str[length]!=0 || (incr>1 && str[length+1]!=0) )  length+=incr;
	}
	length/=incr;
	dwHash = 0;
	do
	{
		dwHash = _rotr( (DWORD)dwHash, 13 );
		// normalize to uppercase if we need to ignore the case
		if( !casesensitive && *((BYTE *)str) >= 'a' )
			dwHash += *((BYTE *)str) - 0x20;
		else
			dwHash += *((BYTE *)str);
		str+=incr;
	} while( --length );
	return dwHash;
}

void Utils::AllocateConsole(LPCSTR pTitle)
{
	// Allocate Console Window
	AllocConsole() ;
	AttachConsole(GetCurrentProcessId());
	freopen("CON", "w", stdout) ;
	SetConsoleTitleA(pTitle);

	// Resize console (max length)
	COORD cordinates = {80, 32766};
	HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
	SetConsoleScreenBufferSize(handle, cordinates);
}

DWORD Utils::FindPattern( DWORD dwStart, DWORD dwLen, BYTE* pszPatt, char pszMask[] )
{
	unsigned int i = NULL;
	int iLen = strlen( pszMask ) - 1;

	for( DWORD dwRet = dwStart; dwRet < dwStart + dwLen; dwRet++ )
	{
		if( *(BYTE*)dwRet == pszPatt[i] || pszMask[i] == '?' )
		{
			if( pszMask[i+1] == '\0' )
				return( dwRet - iLen );
			i++;
		}
		else
			i = NULL;
	}
	return NULL;
}

unsigned int Utils::oneAtATimeHash(const char *inpStr)
{
	unsigned int value = 0, temp = 0;
	for(size_t i = 0; inpStr[i] != 0; ++i)
	{
		char ctext = tolower(inpStr[i]);
		temp = ctext + value;
		value = temp << 10;
		temp = temp + value;
		value = temp >> 6;
		value = value ^ temp;
	}
	temp = value << 3;
	temp = temp + value;
	unsigned int temp2 = temp >> 11;
	temp = temp2 ^ temp;
	temp2 = temp << 15;
	value = temp2 + temp;
	if(value < 2)
		return value + 2;
	return value;
}

DWORD Utils::GetSizeOfCode( HANDLE hHandle )
{
	HMODULE hModule = (HMODULE)hHandle;

	if ( !hModule )
		return NULL;

	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER( hModule );

	if( !pDosHeader )
		return NULL;

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS( (LONG)hModule + pDosHeader->e_lfanew );

	if( !pNTHeader )
		return NULL;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;

	if( !pOptionalHeader )
		return NULL;

	return pOptionalHeader->SizeOfCode;
}

DWORD Utils::OffsetToCode( HANDLE hHandle )
{
	HMODULE hModule = (HMODULE)hHandle;

	if ( !hModule )
		return NULL;

	PIMAGE_DOS_HEADER pDosHeader = PIMAGE_DOS_HEADER( hModule );

	if( !pDosHeader )
		return NULL;

	PIMAGE_NT_HEADERS pNTHeader = PIMAGE_NT_HEADERS( (LONG)hModule + pDosHeader->e_lfanew );

	if( !pNTHeader )
		return NULL;

	PIMAGE_OPTIONAL_HEADER pOptionalHeader = &pNTHeader->OptionalHeader;

	if( !pOptionalHeader )
		return NULL;

	return pOptionalHeader->BaseOfCode;
}

bool Utils::FileExists(std::string pFileName)
{
	std::ifstream sFile(pFileName);
	return false;
}

std::string Utils::GetCurrentDir()
{
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of("\\/");
	return std::string(buffer).substr(0, pos);
}


void Utils::DumpFile(char* name, const char* buffer, int length) {
	std::ofstream myFile(name, std::ios::out | std::ios::binary);
	myFile.write(buffer, length);
	myFile.close();
}


DWORD Utils::FindPattern(DWORD dwStart, DWORD dwLen, BYTE* pszPatt, const char pszMask[])
{
	unsigned int i = NULL;
	int iLen = strlen(pszMask) - 1;

	for (DWORD dwRet = dwStart; dwRet < dwStart + dwLen; dwRet++)
	{
		if (*(BYTE*)dwRet == pszPatt[i] || pszMask[i] == '?')
		{
			if (pszMask[i + 1] == '\0')
				return(dwRet - iLen);
			i++;
		}
		else
			i = NULL;
	}
	return NULL;
}