#include "StdAfx.h"
#include "Encryption.h"
namespace ArcheAge
{
	namespace AGH
	{
		///--------
		//пакет до ксора, смотреть trace 11 и trace12
		//len=0x23(35)

		//CPU Dump
		//Address Hex dump ASCII(OEM - США)
		//           hash count type
		//             vv    vv vvvvv
		//               CRC
		//                vv
		//0016FC20  00 05 B4 9F|3E 01 01 00|00 00 00 00|00 00 00 00|  +?>
		//0016FC30  00 00 00 03|00 6E 6F 70|00 00 00 00|00 00 00 00|     nop
		//0016FC40  00 00 00 00|

		//0x9F, 0x3E, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x6E, 0x6F, 0x70

		//пакет после подсчета контрольной суммы пакета, считаются байты(9F3E010100000000000000000000000003006E6F70)
		//начиная с адреса 0016FC23 len = 15(21), нулевые байты не считают?
		//CPU Dump
		//Address   Hex dump                                         ASCII(OEM - США)
		//                vv
		//0016FC20  00 05 73 9F|3E 01 01 00|00 00 00 00|00 00 00 00|  +?>
		//0016FC30  00 00 00 03|00 6E 6F 70|00 00 00 00|00 00 00 00|     nop
		//0016FC40  00 00 00 00|

		/*13.07.2018 - подсчитывает правильно - D4
		CPU Dump
		Address   Hex dump                                         ASCII (OEM - США)
						vv-начинаем отсюда
		444CFCD8  D4 01 55 00|01 00 01 08|00 78 32 75|69 2F 68 75| ╘U   x2ui/hu
		444CFCE8  64 00                                            d

		// подсчет контрольной суммы в EAX, по выходу используется только AL
		int __usercall CRC8_B8EF@<eax>(int crc@<eax>, int data@<ecx>, int size@<ebp>)
		{
			*(_DWORD *)(size + 12);
			return *(unsigned __int8 *)(data + *(_DWORD *)(size + 8)) + 19 * crc;
		}
		*/
		/// <summary>
		/// Подсчет контрольной суммы пакета, используется в шифровании пакетов DD05
		/// </summary>
		byte _CRC8_(byte* data, int size)
		{
			int len = size;
			uint32_t checksum = 0;
			for (int i = 0; i <= len - 1; i++)
			{
				checksum = checksum * 0x13;
				checksum += data[i];
			}
			return (byte)(checksum);
		}

		//byte _CRC8_(byte* data)
		//{
		//	int len = data.Length;
		//	UInt32 checksum = 0;
		//
		//	for (int i = 0; i <= len - 1; i++)
		//	{
		//		checksum = checksum * 0x13;
		//		checksum += data[i];
		//	}
		//	return (byte)(checksum);
		//}

		//=====================================================================================
		/// <summary>
		/// вспомогательная подпрограмма для encode/decode серверных пакетов
		/// </summary>
		/// <param name="cry"></param>
		/// <returns></returns>

		byte Encryption::Inline(unsigned int cry)
		{
			cry += 0x2FCBD5U;
			byte n = (cry >> 0x10);
			n = (byte)(n & 0x0F7);
			return (byte)(((int)n == 0) ? 0x0FE : n);
		}

		//--------------------------------------------------------------------------------------
		/// <summary>
		/// подпрограмма для encode/decode серверных пакетов, правильно шифрует и расшифровывает серверные пакеты DD05 для версии 3.0.3.0
		/// </summary>
		/// <param name="bodyPacket">адрес начиная с байта за DD05</param>
		/// <returns>возвращает адрес на подготовленные данные</returns>

		byte* Encryption::StoCDecrypt(byte* BodyPacket, int Length)
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

		//=====================================================================================
		///шифрует и расшифровывает клиентские пакеты 0005 - не подтерждено
		///

		//byte* CtoSDecrypt(byte* bodyPacket, uint_t unkKey)
		//{
		//	byte* array = new byte[bodyPacket.Length];
		//	uint cry = ((uint)(unkKey + (ulong)bodyPacket.Length) * unkKey) ^ 0x75A01F21u;
		//	int n = 4 * (bodyPacket.Length / 4);
		//	for (int i = n - 1; i >= 0; i--)
		//		array[i] = (byte)(bodyPacket[i] ^ (uint)Inline(ref cry));
		//	for (int i = n; i < bodyPacket.Length; i++)
		//		array[i] = (byte)(bodyPacket[i] ^ (uint)Inline(ref cry));
		//	return array;
		//}

		// --------------------------------------------------------------------------------------------------------
		//--------------------------- непроверенные !!! --------------------------
		// --------------------------------------------------------------------------------------------------------
		//public static uint CheckSum(ushort[] data, uint size)
		//{
		//    ushort[] m_data = new ushort[5];
		//    uint m_size = size;
		//    uint v4 = 0;
		//    uint v5 = 0;
		//    uint v6 = 0;
		//    if ((m_size / 2) < 2)
		//    {
		//        m_data = data;
		//    }
		//    else
		//    {
		//        uint len = ((uint)(m_size - 4) >> 2) + 1;
		//        m_size = size - 4 * len;
		//        m_data = data;
		//        do
		//        {
		//            v4 += m_data;
		//            v5 += m_data[1];
		//            m_data += 2;
		//            len--;
		//        }
		//        while (Len);
		//    }
		//    if (m_size > 1)
		//    {
		//        v6 = m_data;
		//        m_data++;
		//        m_size -= 2;
		//    }
		//    ushort crc = v4 + v5 + v6;
		//    if (m_size > 0)
		//        crc += (byte)m_data;
		//    return ~(crc + (crc >> 16) + ((crc + (crc >> 16)) >> 16));
		//}

		/*
			* ///из xlcommon.dll
		unsigned int __stdcall XlPing::CheckSum(unsigned __int16 * data, int Size)
		{
			int m_Size; // esi
			int v4; // edi
			int v5; // ebx
			int v6; // ebp
			unsigned int Len; // ecx
			unsigned __int16 *m_data; // eax
			unsigned int crc; // ebp

			m_Size = Size;
			v4 = 0;
			v5 = 0;
			v6 = 0;
			if (Size / 2 < 2 )
			{
				m_data = data;
			}
			else
			{
				Len = ((unsigned int)(Size - 4) >> 2) + 1;
				m_Size = Size - 4 * Len;
				m_data = data;
				do
				{
					v4 += * m_data;
					v5 += m_data[1];
					m_data += 2;
					--Len;
				}
				while (Len );
			}
			if (m_Size > 1 )
			{
				v6 = * m_data;
				++m_data;
				m_Size -= 2;
			}
			crc = v4 + v5 + v6;
			if (m_Size > 0 )
			crc += * (unsigned __int8 *)m_data;
			return ~((unsigned __int16) crc + (crc >> 16) + (((unsigned __int16) crc + (crc >> 16)) >> 16));
			}
		*/

		byte Crc8_(byte* data, int size)
		{
			byte checksum = 0;
			for (int i = 0; i <= size - 1; i++)
				checksum += data[i];

			return (byte)(-checksum);
		}

		///
		/// This enum is used to indicate what kind of checksum you will be calculating.
		/// 
		/// образующий многочлен
		enum CRC8_POLY
		{
			///для контроля для сообщения "123456789"  = byte[] {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39}
			CRC8_CCITT = 0x07,       // 0xFE
			CRC8_SAE_J1850 = 0x1D,   // 0x37
			CRC8_DALLAS_MAXIM = 0x31,// 0xA2
			CRC8 = 0xd5,             // 0xBC
			CRC_8_WCDMA = 0x9b       // 0xEA
		};
	}
}