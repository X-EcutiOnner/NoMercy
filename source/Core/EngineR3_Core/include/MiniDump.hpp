#pragma once

namespace NoMercyCore
{
	using TMiniDumpCallback = std::function<void(bool, int, std::wstring)>;

	class CMiniDump
	{
	public:
		static bool TriggerSEH(int nErrorCode);
		static bool InitMiniDumpHandler();
		static void RegisterMiniDumpCallback(TMiniDumpCallback fn);
	};
};
