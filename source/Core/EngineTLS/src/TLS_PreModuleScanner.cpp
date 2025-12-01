#include "../include/PCH.hpp"
#include "../include/TLS.hpp"
#include "../include/TLS_WinAPI.hpp"
#include "../../EngineR3_Core/include/Defines.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"

#define MAX_MODULES 1000 // Maximum number of modules that can be enumerated

namespace NoMercyTLS
{
	static LDR_DATA_TABLE_ENTRY* s_pLoadedModules[MAX_MODULES]{ 0 };
	static SIZE_T s_cbLoadedModuleCount = 0;

	void CopyModuleData(LDR_DATA_TABLE_ENTRY* pModule)
	{
		if (!pModule || !pModule->DllBase)
			return;

		if (s_cbLoadedModuleCount < MAX_MODULES)
		{
			RtlCopyMemory(&s_pLoadedModules[s_cbLoadedModuleCount++], pModule, sizeof(LDR_DATA_TABLE_ENTRY));
		}
	}

	LDR_DATA_TABLE_ENTRY** TLS_GetLoadedModules()
	{
		return s_pLoadedModules;
	}
	SIZE_T TLS_GetLoadedModuleCount()
	{
		return s_cbLoadedModuleCount;
	}

	void TLS_ScanModules()
	{
		TLS_EnumerateModules(nullptr, [](LDR_DATA_TABLE_ENTRY* pModule, LPVOID lpParam) {
			if (!pModule || !pModule->DllBase)
				return;

#ifdef _DEBUG
			TLS_LOG("%ls", pModule->FullDllName.Buffer);
#endif
			CopyModuleData(pModule);
		});
	}
}
