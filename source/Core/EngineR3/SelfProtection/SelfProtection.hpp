#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace NoMercy
{
	class CSelfProtection
	{
		public:
			static bool InitializeAntiDump(HMODULE hModule);
			static bool IsDumpTriggered();

			static void initialize_protection(HMODULE mdl, const std::string& section_to_encrypt);
			static void MakePePacked(HMODULE hModule);
			static void ProtectSelfPE(HMODULE hModule);
			static void DestroyIAT(HMODULE hModule);
			static bool SetupEntrypointWatchdog();
			static void HideModuleLinks(HMODULE hModule);
			static bool CheckSelfPatchs();
			static void InitializeMutation(uint32_t seed = 1337);
			static bool InitializeAntiMemoryTamper();
			static bool InitializeCFGHook(PVOID pvDllBase);
			static bool InitializeHiddenMemoryExecutor(LPVOID pvFunc);
	};
};
