#pragma once
#include "../../EngineR3_Core/include/Pe.hpp"
#include "../../EngineR3_Core/include/FileVerifier.hpp"
#include "PatternScanner.hpp"
#include "MemoryHelper.hpp"

#undef GetCommandLine

namespace NoMercy
{
	enum class EProcessAccessType : uint8_t
	{
		NONE,
		USER
		// KERNEL
	};

	enum class EProcessType : uint8_t
	{
		UNKNOWN,
		NATIVE_32,
		NATIVE_64,
		WOW64
	};

	struct SSignatureContext
	{
		bool bVerified;
		std::vector <SCertContext> vecSignatures;
	};
	struct SVersionContext
	{
		std::wstring stCompanyName;
		std::wstring stFileDescription;
		std::wstring stFileVersion;
		std::wstring stProductName;
		std::wstring stProductVersion;
	};

	class CThread;
	class CModule;
	class CSection;
	class CHandle;
	class CMitigationPolicy;
	class CPPLPolicy;
	class CToken;
	class CEnvironment;
	class CWindow;
	class CFile;

	class CProcess
	{
	public:
		CProcess(const EProcessAccessType kAccessType = EProcessAccessType::USER);
		CProcess(const DWORD dwProcessID, const DWORD dwAccessMask, const EProcessAccessType kAccessType = EProcessAccessType::USER);
		CProcess(const std::wstring& wstName, const DWORD dwAccessMask, const EProcessAccessType kAccessType = EProcessAccessType::USER);
		CProcess(const HANDLE hProcess);
		virtual ~CProcess();

		// moveable
		CProcess(CProcess&& other) noexcept;
		CProcess& operator=(CProcess&& other) noexcept;

		bool IsValid() const;
		explicit operator bool() const;

		bool IsX86();
		bool IsX64();
		bool IsWoW64();
		std::wstring GetArch();
		
		std::shared_ptr <CFile> GetFile();

		DWORD GetID() const;
		DWORD GetSID() const;
		HANDLE GetUserHandle() const;
		std::wstring GetName() const;
		std::wstring GetFullName() const;
		std::wstring GetPath() const;
		ptr_t GetBaseAddress() const;
		DWORD GetParentPID() const;
		std::wstring GetParentName() const;
		QWORD GetStartTime() const;
		std::wstring GetWorkingDirectory() const;
		std::wstring GetCommandLine() const;
		bool QueryDigitalSignature(SSignatureContext& ctx) const;
		bool QueryFileVersion(SVersionContext& ctx) const;
		std::wstring GetProcessSID();
		std::wstring GetProcessOwner();
		std::wstring GetProcessUserName();
		bool IsProcessElevated();
		DWORD GetProcessIntegrityLevel();
		std::vector <std::wstring> GetprocessIconDumps();
		double GetCpuUsage();
		double GetMemoryUsage();
		std::wstring GetProtectionStatus();
		bool IsProtectedProcess();
		bool IsSecureProcess();
		ptr_t GetPebAddress() const;
		ptr_t GetEProcessAddress();
		ptr_t GetInstrumentationCallback();
		DWORD GetParentConsolePID();
		std::wstring GetPermissions();
		bool GetMandatoryPolicy(PACCESS_MASK Mask);
		std::wstring GetEnvironmentVariables();
		std::wstring GetPerformanceStats();

		HANDLE CreateThread(ptr_t lpStartAddress, ptr_t lpParameter) const;
		bool Terminate(DWORD dwExitCode) const;
		bool Suspend() const;
		bool Resume() const;
		bool IsRunning() const;

		template <typename T>
		T GetPEB() const;

		void EnumerateThreads(std::function<bool(std::shared_ptr <CThread> thread)> fn);
		auto GetThreads();

		void EnumerateModules(std::function<bool(std::shared_ptr <CModule> mdl)> fn);
		auto GetModules();

		void EnumerateSections(std::function<bool(std::shared_ptr <CSection> section)> fn);
		auto GetSections();

		void EnumerateHandles(std::function<bool(std::shared_ptr <CHandle> handle)> fn);
		auto GetHandles();

		std::map <std::wstring, std::wstring> GetMitigationPolicies();

		void EnumeratePPLPolicies(std::function<bool(std::shared_ptr <CPPLPolicy> policy)> fn);
		auto GetPPLPolicies();

		void EnumerateTokens(std::function<bool(std::shared_ptr <CToken> token)> fn);
		auto GetTokens();

		void EnumerateEnvironments(std::function<bool(std::shared_ptr <CEnvironment> env)> fn);
		auto GetEnvironments();

		void EnumerateWindows(std::function<bool(std::shared_ptr <CWindow> window)> fn);
		auto GetWindows();

		auto GetMemoryManager() const { return m_spMemoryHelper; };

	protected:
		bool __Open();
		bool __SetProcessBitness();
		std::vector <uint8_t> __GetTokenInformation(HANDLE hToken, TOKEN_INFORMATION_CLASS eTokenType);
		std::vector <uint8_t> __GetProcessInformation(TOKEN_INFORMATION_CLASS eTokenType);

	private:
		EProcessAccessType		m_nProcAccessType;
		EProcessType			m_nProcType;
		DWORD					m_dwProcessID;
		DWORD					m_dwSessionID;
		DWORD					m_dwAccessMask;
		HANDLE					m_hProcessUser;
		ptr_t					m_pBaseAddress;
		ptr_t					m_pPEB32Address;
		ptr_t					m_pPEB64Address;
		
		std::shared_ptr <CMemoryHelper>						m_spMemoryHelper;
		std::vector <std::shared_ptr <CThread>>				m_vecThreads;
		std::vector <std::shared_ptr <CModule>>				m_vecModules;
		std::vector <std::shared_ptr <CSection>>			m_vecSections;
		std::vector <std::shared_ptr <CHandle>>				m_vecHandles;
		std::vector <std::shared_ptr <CMitigationPolicy>>	m_vecMitigationPolicies;
		std::vector <std::shared_ptr <CPPLPolicy>>			m_vecPPLPolicies;
		std::vector <std::shared_ptr <CToken>>				m_vecTokens;
	};

	static auto GetCurrentProcessManager()
	{
		return stdext::make_unique_nothrow<CProcess>(reinterpret_cast<HANDLE>(NtCurrentProcess()));
	}
}
