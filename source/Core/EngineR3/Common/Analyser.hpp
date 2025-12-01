#pragma once
#include <map>
#include <mutex>
#include "../Scanner/ScannerInterface.hpp"

namespace NoMercy
{
	enum class EAnalyseTypes : uint8_t
	{
		ANALYSE_NULL,
		ANALYSE_PROCESS_CREATE,
		ANALYSE_PROCESS_TERMINATE,
		ANALYSE_THREAD,
		ANALYSE_MODULE,
		ANALYSE_MODULE_2,
		ANALYSE_DRIVER,
		ANALYSE_SERVICE,
		ANALYSE_WINDOW,
		ANALYSE_MAX
	};

	enum EStartAddressCheckTypes : uint8_t
	{
		CHECK_TYPE_THREAD,
		CHECK_TYPE_RtlGetFullPathName_U,
		CHECK_TYPE_NtCreateSection,
		CHECK_TYPE_NtMapViewOfSection,
		CHECK_TYPE_WMI,
		CHECK_TYPE_LdrDllNotificationCallback,
		CHECK_TYPE_MANUAL_MAP_SCAN
	};

	struct SCheatProcessHandleCtx
	{
		std::wstring wstObjectName;
		std::wstring wstObjectType;
		std::wstring wstType;
		std::wstring wstAccessRights;
	};
	struct SCheatProcessThreadCtx
	{
		uint32_t nTID;
		uint32_t nPriority;
		double dCPUUsagePerc;
		uint64_t nCyclesDelta;
		std::wstring wstOwnerModuleName;
		std::wstring wstThreadOwnerModuleName;
		std::wstring wstSymbolizedStartAddress;
		std::vector <std::wstring> vecStackTrace;
		std::wstring wstDebugRegisters;
	};
	struct SCheatProcessGeneralCtx
	{
		std::wstring wstName;
		std::wstring wstParentName;
		uint64_t nFileSize;
		std::wstring wstMD5;
		std::wstring wstSignature;
		std::wstring wstVersion;
		std::wstring wstCommandLine;
		std::wstring wstCurrentDirectory;
		uint32_t nIntegrityLevel;
		uint64_t nStartTime;
		uint64_t nOSBootTime;
		uint64_t nGameStartTime;
		std::wstring wstImageType;
		std::wstring wstInstrCallback;
		std::map <std::wstring, std::wstring> mapMitigationList;
	};
	struct STokenPrivilegeInfo
	{
		std::wstring wstName;
		std::wstring wstDisplayName;
		bool bEnabled{ false };
	};
	struct STokenGroupInfo
	{
		std::wstring wstName;
		std::wstring wstSID;
		std::wstring wstType;
		uint32_t dwAttributes{ 0 };
		bool bEnabled{ false };
	};
	struct SCheatProcessTokenCtx
	{
		std::wstring wstUser;
		std::wstring wstSID;
		std::wstring wstUserProfile;
		uint32_t nSession;
		bool bElevated;
		bool bVirtualized;
		std::vector <std::shared_ptr <STokenPrivilegeInfo>> vecPrivileges;
		std::vector <std::shared_ptr <STokenGroupInfo>> vecGroups;
	};
	struct SCheatProcessModuleCtx
	{
		std::wstring wstName;
		std::wstring wstVersion;
		std::wstring wstModuleInfo;
		std::wstring wstMD5;
		std::wstring wstSignature;
	};
	struct SCheatProcessMemoryRegionCtx
	{
		uint64_t pBase;
		uint64_t nSize;
		uint32_t nType;
		uint32_t nProtection;
		uint32_t nState;
		std::wstring wstOwnerModule;
		std::vector <uint8_t> vecDumpMem;
	};
	struct SCheatProcessWindowCtx
	{
		std::wstring wstTitle;
		std::wstring wstClass;
		bool bVisible;
		bool bHung;
		std::wstring wstThreadModule;
		std::wstring wstModuleName;
	};
	struct SCheatProcessCtx
	{
		std::wstring wstRefID;
		std::wstring wstFileName;
		LPVOID lpFileData;
		SIZE_T nFileSize;
		LPVOID lpMiniDumpData;
		SIZE_T nMiniDumpSize;
		std::vector <std::wstring> vecMemStrings;
		std::vector <std::wstring> vecFileStrings;
		std::vector <std::shared_ptr <SCheatProcessHandleCtx>> vecHandles;
		std::vector <std::shared_ptr <SCheatProcessThreadCtx>> vecThreads;
		std::shared_ptr <SCheatProcessGeneralCtx> spGeneral;
		std::shared_ptr <SCheatProcessTokenCtx> spToken;
		std::vector <std::shared_ptr <SCheatProcessModuleCtx>> vecModules;
		std::vector <std::shared_ptr <SCheatProcessMemoryRegionCtx>> vecMemoryRegions;
		std::vector <std::shared_ptr <SCheatProcessWindowCtx>> vecWindows;
	};

	class CAnalyser : public std::enable_shared_from_this <CAnalyser>
	{
	public:
		CAnalyser() = default;
		virtual ~CAnalyser() = default;

	public:
		void OnWMITriggered(EAnalyseTypes analyseType, std::map <std::wstring /* szType */, std::wstring /* szValue */> mDataMap);

		uint32_t AnalyseShellcode(LPVOID lpCaller, EAnalyseTypes nAnalyseType, const std::wstring& stModuleName);

	public:
		// Hook callbacks
		bool OnThreadCreated(DWORD dwThreadID, HANDLE hThread, PCONTEXT lpRegisters, bool& bSuspicious);
		bool OnModuleLoaded(const std::wstring& wstName, HANDLE hThread, uint8_t nCheckType, bool& bSuspicious);
		bool OnSectionCreated(HANDLE hFile, ULONG ulSectionAttributes, bool& bSuspicious);
		bool OnSectionMapped(LPVOID lpBase, LPVOID lpArbitraryUserPointer, bool& bSuspicious);
		bool OnExceptionThrowed(PEXCEPTION_RECORD ExceptionInfo, bool& bSuspicious);
		bool OnConnected(const std::wstring& szTargetAddress, uint16_t wPort, bool& bSuspicious);
		bool OnWndProcHooked(HWND hWnd, int nIndex, LONG dwNewLong, bool& bSuspicious);
		bool OnModuleRequested(const std::wstring& wstName, bool& bSuspicious);
		bool OnDelayExecution(bool bAlertable, LONGLONG llDelay, DWORD dwCurrentTID, LPVOID lpCaller, bool& bSuspicious);
		bool IsApcAllowed(PVOID ApcRoutine);

	public:
		// WMI callbacks
		void OnProcessCreateOrTerminate(std::shared_ptr <SProcessCallbackCtx> ctx);
		void OnThreadCreate(std::shared_ptr <SThreadCallbackCtx> ctx);
		void OnModuleLoad(std::shared_ptr <SModuleCallbackCtx> ctx);
		void OnDriverLoad(std::shared_ptr <SDriverCallbackCtx> ctx);

	protected:
		// Hook analyse available checkers
		bool __CanAnalyseThread(const DWORD c_dwThreadID);
		bool __CanAnalyseModule(const std::wstring& c_wstModuleName);
		bool __CanAnalyseSection(const HANDLE c_hFile);
		bool __CanAnalyseMappedSection(const LPVOID c_lpMemory);
		bool __CanAnalyseException(const PEXCEPTION_RECORD c_pExceptionInfo);
		bool __CanAnalyseConnection(const std::wstring& c_stAddress);
		bool __CanAnalyseWindow(const HWND c_hWnd);
		bool __CanAnalyseModuleRequest(const std::wstring& c_wstName);
		bool __CanAnalyseDelayExecution(const LPVOID c_lpCallerFunc);

	private:
		mutable std::recursive_mutex m_mtxThread;
		mutable std::recursive_mutex m_mtxModule;
		mutable std::recursive_mutex m_mtxSection;
		mutable std::recursive_mutex m_mtxMappedSection;
		mutable std::recursive_mutex m_mtxException;
		mutable std::recursive_mutex m_mtxConnection;
		mutable std::recursive_mutex m_mtxWindow;
		mutable std::recursive_mutex m_mtxModuleRequest;
		mutable std::recursive_mutex m_mtxDelayExecution;

		std::vector <DWORD>					m_analysed_threads;
		std::vector <std::wstring>			m_analysed_modules;
		std::vector <HANDLE>				m_analysed_sections;
		std::vector <LPVOID>				m_analysed_section_mems;
		std::vector <PEXCEPTION_RECORD>		m_analysed_exceptions;
		std::vector <std::wstring>			m_analysed_connections;
		std::vector <HWND>					m_analysed_windows;
		std::vector <std::wstring>			m_analysed_module_requests;
		std::vector <LPVOID>				m_analysed_delayed_executions;

		std::vector <std::wstring> m_analysed_cheat_files;
	};
};
