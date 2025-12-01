#pragma once

namespace NoMercy
{
	class CHookScanner : public std::enable_shared_from_this <CHookScanner>
	{
	public:
		enum class EHookScannerTypes : uint8_t
		{
			NONE,
			INLINE,
			EAT,
			IAT,
			VEH,
			ALL
		};

		struct HOOK_INFO
		{
			PVOID pvFunc{ nullptr };
			EHookScannerTypes nType { 0 };
			std::string stTypeName;
		};

		struct ExceptionRule
		{
			PVOID pvProcedureAddr{ nullptr };
			std::wstring wstFuncName{ L"" };
			BOOLEAN bFindSubstr{ FALSE };
			BOOLEAN bFindByAddr{ TRUE };
		};

		using THookScanCallback = std::function<void(HOOK_INFO*)>;
		
	public:
		CHookScanner();
		virtual ~CHookScanner();

		bool AddExceptionRule(const ExceptionRule& Rules); 
		bool AddExceptionRules(const std::vector <ExceptionRule>& Rules);
		bool IsKnownTempModuleName(const std::wstring& wstName);

		bool IsScannerActive();
		bool StartScanner(EHookScannerTypes, THookScanCallback, PVOID, std::vector <std::wstring>, std::vector <PVOID>&);
		void StopScanner();

	protected:
		bool __IsPrologueWhole(const DWORD_PTR base);
		bool __ScanForHooks();
		bool __SetFields(EHookScannerTypes, THookScanCallback, PVOID, std::vector <std::wstring>, std::vector <PVOID>&);
		void __ClearFields();

		DWORD					HookScannerThreadRoutine(void);
		static DWORD WINAPI		StartHookScannerThreadRoutine(LPVOID);

	private:
		bool m_bIsActive{ false };
		THookScanCallback m_pvCallback{ nullptr };
		EHookScannerTypes m_nTypeOfScan{ EHookScannerTypes::NONE };
		PVOID m_pvSpecificAddr{ nullptr };
		std::vector <std::wstring> m_VecTargetModules{};
		std::multimap <PVOID, std::tuple <std::string, std::string>> m_mmImportsList{};
		std::multimap <PVOID, std::string> m_mmExportsList{};
		std::vector <PVOID> m_vecVehList{};
		std::vector <ExceptionRule> m_vecExceptionRules{};
		PVOID m_pvLastVEH{ nullptr };
		std::map <HMODULE, std::wstring> m_mapTempModules;
		std::vector <std::wstring> m_vecTempModules;
		std::vector <PVOID> m_vecDetectedInlineHooks;
		std::vector <PVOID> m_vecDetectedEatHooks;
		std::vector <PVOID> m_vecDetectedIatHooks;
		std::vector <PVOID> m_vecDetectedVehHooks; 
	};
};
