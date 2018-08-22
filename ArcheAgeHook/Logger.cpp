// ==========================================================
// Logging Class 
//		version 0.1
//
// by NoFaTe
// ==========================================================

// TODO: Recode this properly

#include "StdAfx.h"

#define DEBUG 1

#define BLACK 0
#define BLUE 1
#define GREEN 2
#define CYAN 3
#define RED 4
#define MAGENTA 5
#define BROWN 6
#define LIGHTGREY 7
#define DARKGREY 8
#define LIGHTBLUE 9
#define LIGHTGREEN 10
#define LIGHTCYAN 11
#define LIGHTRED 12
#define LIGHTMAGENTA 13
#define YELLOW 14
#define WHITE 15
#define BLINK 128

bool isLogging = false;

void setColor(unsigned int color)
{
   HANDLE screen = GetStdHandle(STD_OUTPUT_HANDLE);
   SetConsoleTextAttribute(screen, color);
}

void Logger(unsigned int lvl, const char* caller, const char* logline, ...)
{
	// Check if debug is turned on
	if ( lvl == lDEBUG && DEBUG == 0 )
		return;

	while(isLogging)
	{
		Sleep(10);
	}

	isLogging = true;
	FILE *file; 
	file = fopen("AGHEmu.log","a+");
	char timeStr[9];
	char logOut[1024];
	_strtime( timeStr );
	setColor(DARKGREY);
	printf("[%s] ", timeStr);
	fprintf(file, "[%s] ", timeStr);
	setColor(LIGHTGREY);
	printf("%s: ", caller);
	fprintf(file, "%s: ", caller);

	if ( lvl == lINFO )
		setColor(WHITE);
	else if ( lvl == lWARN )
		setColor(YELLOW);
	else if ( lvl == lERROR )
		setColor(RED);
	else if ( lvl == lDEBUG )
		setColor(GREEN);

	va_list argList;
	va_start(argList, logline);
	vsnprintf(logOut, 1024, logline, argList);
	va_end(argList);
	printf("%s\n", logOut);
	fprintf(file, "%s\n", logOut);
	fclose(file);
	isLogging = false;
}