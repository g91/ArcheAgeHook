#include "stdafx.h"
#include "Hooks.h"

unsigned long ModuleThread(void*)
{
	// Allocate a new console window for debugging purposes
	Utils::AllocateConsole("ArcheAgeAGH - Debug Console");
	Logger(lINFO, "AGH", "Starting ArcheAge Hook");

	Logger(lINFO, "AGH", "Hooking ArcheAge CreateWindowEx");
	ArcheAge::AGH::Hooks::HookCreateWindowEx();

	Logger(lINFO, "AGH", "Hooking ArcheAge Packets");
	ArcheAge::AGH::Hooks::HookPackets();

	return 0;
}

DWORD deinitThread(LPVOID lpArguments)
{
	return 0;
}

unsigned long ModuleTestThread(void*)
{
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleThread, 0, 0, NULL);
	return 0;
}

__declspec(dllexport) void start()
{
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleTestThread, 0, 0, NULL);
}

BOOL WINAPI DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpvReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	{
		DisableThreadLibraryCalls(hModule);
		CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)ModuleTestThread, lpvReserved, 0, NULL);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		DisableThreadLibraryCalls(hModule);
	}
	break;
	}
	return TRUE;
}