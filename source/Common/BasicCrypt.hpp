#pragma once
#include <cstdint>

namespace BasicCrypt
{
	template<typename T>
	static inline void rol(T& value, uint32_t places)
	{
		places = places % (8 * sizeof(value));
		value = (value << places) | (value >> (8 * sizeof(value) - places));
	}

	template<typename T>
	static inline void ror(T& value, uint32_t places)
	{
		places = places % (8 * sizeof(value));
		value = (value >> places) | (value << (8 * sizeof(value) - places));
	}
	static uint32_t CustomHash(char* data)
	{
		uint32_t ret = 0;
		while (*data)
		{
			char add = *data;
			if (add >= 'a')
				add -= 0x20;
			ret += add;
			ret ^= 0x9F1A3A39;
			rol(ret, add);
			ret ^= 0x10381259;
			ror(ret, 23);
			ret ^= 0x435EC420;
			rol(ret, 17);
			data++;
		}
		return ret;
	}

	static void DecryptBuffer(uint8_t * lpBuf, size_t dwSize, uint8_t pKey)
	{
		for (size_t i = 0; i < dwSize; i++)
		{
			lpBuf[i] ^= pKey;
			lpBuf[i] += (uint8_t)i;
			lpBuf[i] ^= (uint8_t)i + 6;
		}
	}

	static void EncryptBuffer(uint8_t * lpBuf, size_t dwSize, uint8_t pKey)
	{
		for (size_t i = 0; i < dwSize; i++)
		{
			lpBuf[i] ^= (uint8_t)i + 6;
			lpBuf[i] -= (uint8_t)i;
			lpBuf[i] ^= pKey;
		}
	}
}
