#include "Hooks.h"
#include "Encryption.h"

//////////////////////////////////////////////////////////////////////////
using namespace std;
using namespace ArcheAge;
//////////////////////////////////////////////////////////////////////////
HWND(WINAPI * rCreateWindowEx) (DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam);

HWND WINAPI cCreateWindowEx(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
	if (lpWindowName)
	{
		char sTitle[256];
		sprintf(sTitle, "ArcheAgeAGH [Build %d]", 1);

		lpWindowName = sTitle;
	}

	return rCreateWindowEx(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

//////////////////////////////////////////////////////////////////////////

typedef int (WINAPI* t_WSARecv)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
typedef int (WINAPI* t_WSASend)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

t_WSASend o_WSASend;
t_WSARecv o_WSARecv;

//////////////////////////////////////////////////////////////////////////
int rc = 0;
int WINAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine){
	
	Logger(lINFO, "AGH", "Recv Packet S > C");
	//Utils::HexDump((void*)lpBuffers->buf, lpBuffers->len);

	char test[100];
	ZeroMemory(test, 100);
	sprintf(test, "logs\\Recv\\WSARecv_%i.bin", rc);
	Utils::DumpFile(test, lpBuffers->buf, lpBuffers->len);


	byte* buff = new byte[lpBuffers->len];
	ZeroMemory(buff, lpBuffers->len);
	memcpy(buff, lpBuffers->buf, lpBuffers->len);
	buff = ArcheAge::AGH::Encryption::StoCDecrypt(buff, lpBuffers->len);

	ZeroMemory(test, 100);
	sprintf(test, "logs\\Recv\\Decrypt\\Recv_%i.bin", rc);
	Utils::DumpFile(test, (const char*)buff, lpBuffers->len);

	rc++;
	return o_WSARecv(s, lpBuffers, dwBufferCount, lpNumberOfBytesRecvd, lpFlags, lpOverlapped, lpCompletionRoutine);
}

int sc = 0;
int WINAPI hook_WSASend(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesSent, DWORD dwFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine){

	Logger(lINFO, "AGH", "Send Packet C > S");
	//Utils::HexDump((void*)lpBuffers->buf, lpBuffers->len);

	char test[100];
	ZeroMemory(test, 100);
	sprintf(test, "logs\\WSASend_%i.bin", sc);
	Utils::DumpFile(test, lpBuffers->buf, lpBuffers->len);

	byte* buff = new byte[lpBuffers->len];
	ZeroMemory(buff, lpBuffers->len);
	memcpy(buff, lpBuffers->buf, lpBuffers->len);
	buff = ArcheAge::AGH::Encryption::StoCDecrypt(buff, lpBuffers->len);


	sc++;
	return o_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
}

typedef byte* (__cdecl* t_Encrypthook)(DWORD a2, DWORD a3);
t_Encrypthook o_Encrypthook;

byte* buff;
int testc = 0;
__declspec(naked) byte* __cdecl Encrypthook(DWORD a2, DWORD a3){

	__asm pushad

	Logger(lINFO, "AGH", "===========================================");
	Logger(lINFO, "AGH", "Encrypt hook (%i): a2: 0x%08X a3: 0x%08X", testc, a2, a3);
	Logger(lINFO, "AGH", "Encrypt hook (%i) = WSARecv (%i)", testc, rc);
	Logger(lINFO, "AGH", "HexDump: a2: 0x%X a3(0x%X)", a2, a3);
	Utils::HexDump((void*)a2, a3);

	buff = new byte[a3];
	ZeroMemory(buff, a3);
	buff = ArcheAge::AGH::Encryption::StoCDecrypt((byte*)a2, a3);
	Logger(lINFO, "AGH", "Decrypt HexDump: a2: 0x%X a3(0x%X)", a2, a3);
	Utils::HexDump((void*)buff, a3);
	Logger(lINFO, "AGH", "===========================================");
	testc++;

	__asm popad
	_asm jmp o_Encrypthook;
}


//////////////////////////////////////////////////////////////////////////
namespace ArcheAge
{
	namespace AGH
	{
		void Hooks::HookCreateWindowEx()
		{
			while (GetModuleHandle(TEXT("user32.dll")) == 0)
				Sleep(10);

			DWORD sAllocatorAssign = (DWORD)GetProcAddress(GetModuleHandleA("user32.dll"), "CreateWindowExA");
			if (sAllocatorAssign != NULL)
				rCreateWindowEx = (HWND(WINAPI*) (DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam))DetourFunction((PBYTE)sAllocatorAssign, (PBYTE)cCreateWindowEx);
		}

		void Hooks::HookPackets()
		{
			Logger(lINFO, "AGH", "HookPackets GO");
			while(GetModuleHandle(TEXT("ws2_32.dll")) == 0 )
				Sleep(10);

			while (GetModuleHandle(TEXT("crynetwork.dll")) == 0)
				Sleep(10);

			Logger(lINFO, "AGH", "HookPackets dlls loded");
			Logger(lINFO, "AGH", "crynetwork.dll: 0x%08X", GetModuleHandle("crynetwork.dll"));
			Logger(lINFO, "AGH", "crynetwork.dll + Encrypt: 0x%08X", (GetModuleHandle("crynetwork.dll") + 0x8D7EF));

			HMODULE hMainModule = GetModuleHandle("crynetwork.dll");
			DWORD dCodeSize = Utils::GetSizeOfCode(hMainModule);
			DWORD dCodeOffset = Utils::OffsetToCode(hMainModule);
			DWORD dEntryPoint = (DWORD)hMainModule + dCodeOffset;

			Logger(lINFO, "AGH", "crynetwork.dll: hMainModule 0x%08X", hMainModule);
			Logger(lINFO, "AGH", "crynetwork.dll: dCodeSize 0x%08X", dCodeSize);
			Logger(lINFO, "AGH", "crynetwork.dll: dCodeOffset 0x%08X", dCodeOffset);
			Logger(lINFO, "AGH", "crynetwork.dll: dEntryPoint 0x%08X", dEntryPoint);
			Logger(lINFO, "AGH", "crynetwork.dll + Encrypt: 0x%08X", (DWORD)(dEntryPoint + 0x8D7EF));

			DWORD dwEncrypt = Utils::FindPattern((DWORD)dEntryPoint, dCodeSize, (PBYTE)"\x55\x8B\xEC\x51\x53\x56\x8B\xF0", "xxxxxxxx" );
			Logger(lINFO, "AGH", "crynetwork.dll + Encrypt: 0x%08X", dwEncrypt);

			o_Encrypthook = (t_Encrypthook)DetourFunction((PBYTE)(dEntryPoint + 0x8D7EF), (PBYTE)Encrypthook);
			o_WSASend = (t_WSASend)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "WSASend"), (PBYTE)hook_WSASend);
			o_WSARecv = (t_WSARecv)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "WSARecv"), (PBYTE)hook_WSARecv);
		}

	}
}