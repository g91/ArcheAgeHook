#pragma once
//========================================
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#pragma warning(disable : 4996)
#pragma warning(disable : 4099)
#pragma warning(disable : 4800)
//========================================
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
//========================================
#define _WINSOCKAPI_
#include <Windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <fstream>
#include <iostream>
#include <commctrl.h>
#include <time.h>
//========================================
#pragma comment(lib, "ws2_32.lib")
//========================================
#include "Utils.h"
#include "detours.h"
//========================================
#define lINFO 0
#define lWARN 1
#define lERROR 2
#define lDEBUG 4

void Logger(unsigned int lvl, const char* caller, const char* logline, ...);
//========================================