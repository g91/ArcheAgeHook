#include "Hooks.h"

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

byte Inline(unsigned int cry)
{
	cry += 0x2FCBD5U;
	byte n = (cry >> 0x10);
	n = (byte)(n & 0x0F7);
	return (byte)(((int)n == 0) ? 0x0FE : n);
}

byte* StoCDecrypt(byte* BodyPacket, int Length)
{
	//int Length = sizeof(BodyPacket);
	byte* Array = new byte[Length];
	unsigned int cry = (unsigned int)(Length ^ 0x1F2175A0);
	int n = 4 * (Length / 4);
	for (int i = n - 1; i >= 0; i--)
		Array[i] = (byte)((unsigned int)BodyPacket[i] ^ (unsigned int)Inline(cry));
	for (int i = n; i < Length; i++)
		Array[i] = (byte)((unsigned int)BodyPacket[i] ^ (unsigned int)Inline(cry));
	return Array;
}

//////////////////////////////////////////////////////////////////////////
int rc = 0;
int WINAPI hook_WSARecv(SOCKET s, LPWSABUF lpBuffers, DWORD dwBufferCount, LPDWORD lpNumberOfBytesRecvd, LPDWORD lpFlags, LPWSAOVERLAPPED lpOverlapped, LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine){
	
	Logger(lINFO, "AGH", "Recv Packet S > C");
	//Utils::HexDump((void*)lpBuffers->buf, lpBuffers->len);

	char test[100];
	ZeroMemory(test, 100);
	sprintf(test, "logs\\Recv\\WSARecv_%i.bin", rc);
	Utils::DumpFile(test, lpBuffers->buf, lpBuffers->len);

	unsigned char* buff = (unsigned char*)lpBuffers->buf;
	StoCDecrypt(buff, lpBuffers->len);

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

	sc++;
	return o_WSASend(s, lpBuffers, dwBufferCount, lpNumberOfBytesSent, dwFlags, lpOverlapped, lpCompletionRoutine);
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
			while(GetModuleHandle(TEXT("ws2_32.dll")) == 0 )
				Sleep(10);

			o_WSASend = (t_WSASend)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "WSASend"), (PBYTE)hook_WSASend);
			o_WSARecv = (t_WSARecv)DetourFunction((PBYTE)GetProcAddress(GetModuleHandle("ws2_32.dll"), "WSARecv"), (PBYTE)hook_WSARecv);
		}

	}
}