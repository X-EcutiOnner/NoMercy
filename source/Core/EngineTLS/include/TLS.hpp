#pragma once
#ifdef _DEBUG
#define ENABLE_TLS_LOGS
#endif

namespace NoMercyTLS
{
	// Main
	bool IsTlsCompleted();
	void TLS_Routine(PVOID hModule, DWORD dwReason, PVOID pContext);

	// Log
	const char* TLS_BuildStringA(const char* c_szFunction, char* szFormat, ...);
	void TLS_Log(const char* c_szMessage);
	void TLS_Logf(const char* c_szFunction, char* szFormat, ...);

	// Utils
	bool TLS_IsMainModule(HMODULE hModule);
	bool TLS_IsIninModule(DWORD_PTR dwAddress);
	void TLS_EnumerateModules(LPVOID lpParam, void(*cb)(LDR_DATA_TABLE_ENTRY*, LPVOID));
	void TLS_EnumerateThreads(LPVOID lpParam, void(*cb)(DWORD, LPVOID));
	void TLS_EnumerateMemorys(LPVOID lpParam, void(*cb)(PVOID, MEMORY_BASIC_INFORMATION, LPVOID));

	LDR_DATA_TABLE_ENTRY** TLS_GetLoadedModules();
	SIZE_T TLS_GetLoadedModuleCount();

	void TLS_ScanModules();
	void TLS_ScanMemory();
	void TLS_ScanThreads();
	
	// ManualMap / ReMap
	bool TLS_RemapImage(ULONG_PTR ImageBase);
};
