#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "PatternScanner.hpp"

namespace NoMercy
{
	void* CPatternScanner::Resolve(void *address, PatternType type)
	{
		static std::function<void*(void*)>* funcs = nullptr;
		if (!funcs)
		{
			funcs = new (std::nothrow) std::function<void*(void*)>[10];
			funcs[0] = [](void *address) { return CPatternScanner::ResolvePtr<void *>(address); };
			funcs[1] = [](void *address) { return CPatternScanner::ResolvePtr<uint8_t>(address); };
			funcs[2] = [](void *address) { return CPatternScanner::ResolvePtr<uint16_t>(address); };
			funcs[3] = [](void *address) { return CPatternScanner::ResolvePtr<uint32_t>(address); };
			funcs[4] = [](void *address) { return CPatternScanner::ResolvePtr<uint64_t>(address); };
			funcs[5] = [](void *address) { return CPatternScanner::ResolveRelativePtr<void *>(address); };
			funcs[6] = [](void *address) { return CPatternScanner::ResolveRelativePtr<uint8_t>(address); };
			funcs[7] = [](void *address) { return CPatternScanner::ResolveRelativePtr<uint16_t>(address); };
			funcs[8] = [](void *address) { return CPatternScanner::ResolveRelativePtr<uint32_t>(address); };
			funcs[9] = [](void *address) { return CPatternScanner::ResolveRelativePtr<uint64_t>(address); };
		}

		return funcs[(int)type - (int)PatternType::Pointer](address);
	}

	void* CPatternScanner::FindPattern(void *start, void *end, uint8_t *pattern, char *mask, int offset)
	{
		uintptr_t pos = 0;
		size_t searchLen = strlen(mask) - 1;
		void* ret = nullptr;

		for (uintptr_t retAddress = (uintptr_t)start; retAddress < (uintptr_t)end; retAddress++)
		{
			if (IsValidPtr(retAddress))
			{
				if (*(uint8_t *)retAddress == pattern[pos] || mask[pos] == '?')
				{
					if (mask[pos + 1] == '\0')
					{
						ret = Ptr<void *>(retAddress, offset - searchLen);
						break;
					}

					pos++;
				}
				else
					pos = 0;
			}
			else
			{
				pos = 0;
				continue;
			}

			g_winAPIs->Sleep(1);
		}

		return ret;
	}

	void* CPatternScanner::findPattern(void *startAddress, uint32_t scanRange, const Pattern &pattern)
	{
		if (pattern.type == PatternType::None)
			return nullptr;

		size_t len = pattern.pattern.length();
		if (len == 0)
			return nullptr;

		int byteCount = 1;
		DWORD i = 0;
		while (i < len - 1)
		{
			if (pattern.pattern[i] == ' ')
				byteCount++;
			i++;
		}

		std::vector<uint8_t> patt(byteCount + 1);
		std::vector<char> mask(byteCount + 1);

		int offset = 0;
		int bytesCounted = 0;
		i = 0;
		while (i < len)
		{
			if (pattern.pattern[i] == '[')
			{
				offset = bytesCounted;

				i++;
			}

			if (pattern.pattern[i] == '\0')
				break;

			if (pattern.pattern[i] == '?')
			{
				mask[bytesCounted] = '?';
				patt[bytesCounted] = '\0';

				i++;
			}
			else
			{
				if (i >= len - 1)
					return nullptr;

				uint8_t hn = pattern.pattern[i] > '9' ? std::toupper(pattern.pattern[i]) - 'A' + 10 : pattern.pattern[i] - '0';
				uint8_t ln = pattern.pattern[i + 1] > '9' ? std::toupper(pattern.pattern[i + 1]) - 'A' + 10 : pattern.pattern[i + 1] - '0';
				uint8_t n = (hn << 4) | ln;

				mask[bytesCounted] = 'x';
				patt[bytesCounted] = n;

				i += 2;
			}

			bytesCounted++;

			while (i < len && (pattern.pattern[i] == ' ' || pattern.pattern[i] == '\t' || pattern.pattern[i] == '\r' || pattern.pattern[i] == '\n'))
				i++;
		}
		mask[bytesCounted] = '\0';

		void *ret = FindPattern(startAddress, Ptr<void *>(startAddress, scanRange), patt.data(), mask.data(), offset);

		if (pattern.type >= PatternType::Pointer && pattern.type < PatternType::PatternTypeCount)
			ret = Resolve(ret, pattern.type);

		return ret;
	}

	void* CPatternScanner::findPatternSafe(void* startAddress, uint32_t scanRange, const Pattern& pattern)
	{
		void* ret = nullptr;
		__try
		{
			ret = findPattern(startAddress, scanRange, pattern);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ret = nullptr;
		}

		return ret;
	}
};
