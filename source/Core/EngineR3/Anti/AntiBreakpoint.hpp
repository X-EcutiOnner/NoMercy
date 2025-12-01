#pragma once

namespace NoMercy
{
	class CAntiBreakpoint
	{
	public:
		static bool HasHardwareBreakpoint(HANDLE hThread = NtCurrentThread());
		static bool HasEntrypointBreakpoint();
		static bool HasMemoryBreakpoint();
	};
};
