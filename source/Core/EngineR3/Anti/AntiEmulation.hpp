#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace NoMercy
{
	class CAntiEmulation
	{
	public:
		static bool InitTimeChecks(LPDWORD pdwErrorStep);
		static bool InitAntiEmulation(LPDWORD pdwErrorStep);
	};
};
