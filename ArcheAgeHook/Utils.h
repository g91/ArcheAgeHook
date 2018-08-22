#include "StdAfx.h"
#include <fstream>

#ifndef UTILS_H
#define UTILS_H

class Utils
{
public:
	static DWORD FindPattern( DWORD dwStart, DWORD dwLen, BYTE* pszPatt, char pszMask[] );
	static unsigned int oneAtATimeHash( const char* inpStr );
	static DWORD OffsetToCode( HANDLE hHandle );
	static DWORD GetSizeOfCode( HANDLE hHandle );
	static void AllocateConsole(LPCSTR pTitle);
	static void HexDump(void *ptr, int buflen);
	static bool FileExists(std::string pFileName);
	static std::string GetCurrentDir();
	static void RemoveFile(std::string pPath);
	static DWORD Str2Hash(char *str, int length = 0, int casesensitive = 0, int incr = 1);
	static DWORD HookFunction(LPCSTR lpModule, LPCSTR lpFuncName, LPVOID lpFunction, unsigned char *lpBackup);
	static BOOL UnHookFunction(LPCSTR lpModule, LPCSTR lpFuncName, unsigned char *lpBackup);
	static void DumpFile(char* name, const char* buffer, int length);
};

#endif