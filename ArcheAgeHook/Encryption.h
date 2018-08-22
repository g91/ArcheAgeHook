#pragma once
#include "StdAfx.h"

#ifndef AGH_ENC_H
#define AGH_ENC_H

namespace ArcheAge
{
	namespace AGH
	{
		class Encryption
		{
		public:
			static byte Inline(unsigned int cry);
			static byte* StoCDecrypt(byte* BodyPacket, int Length);
		};
	}
}

#endif