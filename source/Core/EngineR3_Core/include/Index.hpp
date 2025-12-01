#pragma once

namespace NoMercyCore
{
	class CCoreIndex
	{
		public:
			static bool Init(const uint8_t nAppType, const HINSTANCE hInstance = nullptr, LPCVOID c_lpModuleInfo = nullptr);
			static void Release();
			static bool IsInitialized();
			static std::tuple <DWORD, DWORD> GetErrorCodes();
	};
};
