#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <cstdint>

namespace NoMercy
{
	class CExceptionHandlers
	{
		public:
			static bool InitExceptionHandlers();
			static bool InitSingleStepHandler();
			static void RemoveExceptionHandlers();
			static void RemoveSingleStepHandler();
	};
};
