#pragma once
#include "StdAfx.h"
#include <stdint.h>
#include "Utils.h"
#include "detours.h"

#ifndef AGH_HOOKS_H
#define AGH_HOOKS_H

namespace ArcheAge
{
	namespace AGH
	{
		class Hooks
		{
		public:
			static void HookCreateWindowEx();
			static void HookPackets();
		};
	}
}

#endif