#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <cstdint>

namespace NoMercy
{
	class CNoMercyIndex
	{
		public:
			// Entrypoint redirectors
			static BOOL Enter();
			static void Exit();
			static void OnThreadAttach(DWORD dwThreadID);

			// Initialization
			static bool InitCore(uint8_t unVersion, LPCVOID c_lpCallbackPtr, LPCVOID c_lpModuleInfo); // Client
			static bool InitTest(); // Test app

			// Finalization
			static bool Release();

			// Utils
			static bool SendNMMessage(int32_t nCode, LPCVOID c_lpMessage);
			static void SetUserData(const wchar_t* c_szUserToken, unsigned int nUserTokenSize);
			static const wchar_t* GetUserSessionID();
	};
};
