#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ProcessHelper.hpp"
#include "FileHelper.hpp"
#include "SectionHelper.hpp"
#include "ModuleHelper.hpp"
#include "ThreadHelper.hpp"
#include "HandleHelper.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ThreadEnumeratorNT.hpp"
#include "../../EngineR3_Core/include/PeSignatureVerifier.hpp"
#include "../../EngineR3_Core/include/FileVersion.hpp"
#include "../../../Common/IconHelper.hpp"

namespace NoMercy
{
	CProcess::CProcess(const EProcessAccessType nAccessType) :
		m_nProcAccessType(nAccessType), m_nProcType(EProcessType::UNKNOWN), m_dwProcessID(0), m_dwAccessMask(0),
		m_hProcessUser(nullptr), m_pBaseAddress(nullptr),
		m_pPEB32Address(nullptr), m_pPEB64Address(nullptr), m_dwSessionID(0)
	{
	}
	CProcess::CProcess(const DWORD dwProcessID, const DWORD dwAccessMask, const EProcessAccessType nAccessType) :
		m_nProcAccessType(nAccessType), m_nProcType(EProcessType::UNKNOWN), m_dwProcessID(dwProcessID), m_dwAccessMask(dwAccessMask),
		m_hProcessUser(nullptr), m_pBaseAddress(nullptr), 
		m_pPEB32Address(nullptr), m_pPEB64Address(nullptr), m_dwSessionID(0)
	{
		__Open();
		m_spMemoryHelper = std::make_shared<CMemoryHelper>(m_hProcessUser);
	}
	CProcess::CProcess(const std::wstring& wstName, const DWORD dwAccessMask, const EProcessAccessType nAccessType) :
		m_nProcAccessType(nAccessType), m_nProcType(EProcessType::UNKNOWN), m_dwProcessID(0), m_dwAccessMask(dwAccessMask),
		m_hProcessUser(nullptr), m_pBaseAddress(nullptr), 
		m_pPEB32Address(nullptr), m_pPEB64Address(nullptr), m_dwSessionID(0)
	{
		m_dwProcessID = CProcessFunctions::GetProcessIdFromProcessName(wstName);
		__Open();
		m_spMemoryHelper = std::make_shared<CMemoryHelper>(m_hProcessUser);
	}
	CProcess::CProcess(const HANDLE hProcess) :
		m_nProcAccessType(EProcessAccessType::NONE), m_nProcType(EProcessType::UNKNOWN), m_dwProcessID(0), m_dwAccessMask(0),
		m_hProcessUser(hProcess), m_pBaseAddress(nullptr), 
		m_pPEB32Address(nullptr), m_pPEB64Address(nullptr), m_dwSessionID(0)
	{
		m_spMemoryHelper = std::make_shared<CMemoryHelper>(m_hProcessUser);
	}
	CProcess::~CProcess()
	{
		if (g_winAPIs)
		{
			if (IS_VALID_HANDLE(m_hProcessUser) && g_winAPIs->CloseHandle)
			{
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(m_hProcessUser);
			}
		}

		m_nProcAccessType = EProcessAccessType::NONE;
		m_nProcType = EProcessType::UNKNOWN;
		m_dwProcessID = 0;
		m_dwAccessMask = 0;
		m_hProcessUser = nullptr;
		m_pBaseAddress = nullptr;
		m_pPEB32Address = nullptr;
		m_pPEB64Address = nullptr;

		m_vecThreads.clear();
		m_vecModules.clear();
		m_vecSections.clear();
		m_vecHandles.clear();
		m_spMemoryHelper.reset();
	}

	CProcess::CProcess(CProcess&& other) noexcept
	{
		*this = std::forward<CProcess>(other);
	}
	CProcess& CProcess::operator=(CProcess&& other) noexcept
	{
		std::swap(m_nProcAccessType, other.m_nProcAccessType);
		std::swap(m_nProcType, other.m_nProcType);
		std::swap(m_dwProcessID, other.m_dwProcessID);
		std::swap(m_dwAccessMask, other.m_dwAccessMask);
		std::swap(m_hProcessUser, other.m_hProcessUser);
		std::swap(m_pBaseAddress, other.m_pBaseAddress);
		std::swap(m_pPEB32Address, other.m_pPEB32Address);
		std::swap(m_pPEB64Address, other.m_pPEB64Address);
		
		std::swap(m_vecThreads, other.m_vecThreads);
		std::swap(m_vecModules, other.m_vecModules);
		std::swap(m_vecSections, other.m_vecSections);
		std::swap(m_vecHandles, other.m_vecHandles);
		std::swap(m_spMemoryHelper, other.m_spMemoryHelper);

		return *this;
	}

	CProcess::operator bool() const
	{
		return IsValid();
	}
	
	bool CProcess::IsValid() const
	{
		return m_hProcessUser;
	}
		
	bool CProcess::IsX86()
	{
		if (m_nProcType == EProcessType::UNKNOWN)
		{
			__SetProcessBitness();
		}
		return m_nProcType == EProcessType::NATIVE_32 || m_nProcType == EProcessType::WOW64;
	}
	bool CProcess::IsX64()
	{
		if (m_nProcType == EProcessType::UNKNOWN)
		{
			__SetProcessBitness();
		}
		return m_nProcType == EProcessType::NATIVE_64;
	}
	bool CProcess::IsWoW64()
	{
		if (m_nProcType == EProcessType::UNKNOWN)
		{
			__SetProcessBitness();
		}
		return m_nProcType == EProcessType::WOW64;
	}
	std::wstring CProcess::GetArch()
	{
		switch (m_nProcType)
		{
		case EProcessType::NATIVE_32:
			return xorstr_(L"x86");
		case EProcessType::NATIVE_64:
			return xorstr_(L"x64");
		case EProcessType::WOW64:
			return xorstr_(L"x86_64");
		default:
			return xorstr_(L"unknown");
		}
	}

	std::shared_ptr <CFile> CProcess::GetFile()
	{
		const auto wstExecutable = this->GetFullName();
		return stdext::make_shared_nothrow<CFile>(wstExecutable, EFileType::FILE_TYPE_MEMORY, this);
	}

	DWORD CProcess::GetID() const
	{
		return m_dwProcessID;
	}
	DWORD CProcess::GetSID() const
	{
		return m_dwSessionID;
	}
	HANDLE CProcess::GetUserHandle() const
	{
		return m_hProcessUser;
	}
	std::wstring CProcess::GetName() const
	{
		if (!m_dwProcessID)
			return {};
		return CProcessFunctions::GetProcessNameFromProcessId(m_dwProcessID);
	}
	std::wstring CProcess::GetFullName() const
	{
		return CProcessFunctions::GetProcessName(m_hProcessUser);
	}
	std::wstring CProcess::GetPath() const
	{
		return NoMercyCore::CApplication::Instance().DirFunctionsInstance()->GetPathFromProcessName(this->GetFullName());
	}
	ptr_t CProcess::GetBaseAddress() const
	{
		auto fnIsWow64Process = [](HANDLE hProcess) {
			if (g_winAPIs->IsWow64Process2)
			{
				USHORT target_info, host_info = 0;
				if (g_winAPIs->IsWow64Process2(hProcess, &target_info, &host_info))
					return target_info != IMAGE_FILE_MACHINE_UNKNOWN; // returns IMAGE_FILE_MACHINE_UNKNOWN if not WOW64 process
			}
			else
			{
				BOOL bRet = FALSE;
				if (!g_winAPIs->IsWow64Process(hProcess, &bRet) || !bRet)
					return false;
			}

			return true;
		};
		if (fnIsWow64Process(m_hProcessUser) || !NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->IsSystemX64())
		{
			ULONG ulBytesRead = 0;
			PROCESS_BASIC_INFORMATION pbi{ 0 };
			if (NT_SUCCESS(g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessBasicInformation, &pbi, sizeof(pbi), &ulBytesRead)))
			{
				SIZE_T cbBytesRead = 0;
				PEB peb{ 0 };
				if (NT_SUCCESS(g_winAPIs->NtReadVirtualMemory(m_hProcessUser, pbi.PebBaseAddress, &peb, sizeof(peb), &cbBytesRead)))
				{
					return (ptr_t)PtrToPtr64(peb.ImageBaseAddress);
				}
			}
		}
		else
		{
			ULONG ulBytesRead = 0;
			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pbi{ 0 };
			if (NT_SUCCESS(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryInformationProcess(
				m_hProcessUser, ProcessBasicInformation, &pbi, sizeof(pbi), &ulBytesRead)))
			{
				SIZE_T cbBytesRead = 0;
				wow64pp::defs::PEB_64 peb{0};
				if (NT_SUCCESS(NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ReadVirtualMemory(
					m_hProcessUser, (PVOID64)pbi.PebBaseAddress, &peb, sizeof(peb), &cbBytesRead)))
				{
					return (ptr_t)peb.ImageBaseAddress;
				}
			}
		}

		return {};
	}
	DWORD CProcess::GetParentPID() const
	{
		return CProcessFunctions::GetProcessParentProcessId(m_dwProcessID);
	}
	std::wstring CProcess::GetParentName() const
	{
		return CProcessFunctions::GetParentProcessName(m_dwProcessID, true);
	}
	QWORD CProcess::GetStartTime() const
	{
		return CProcessFunctions::GetProcessCreationTime(m_hProcessUser);
	}
	std::wstring CProcess::GetWorkingDirectory() const
	{
		const auto peb = this->GetPEB<PPEB>();
		if (!peb)
			return {};

		SIZE_T cbReadSize = 0;
		RTL_USER_PROCESS_PARAMETERS rupr{ 0 };
		auto ntStatus = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, peb->ProcessParameters, &rupr, sizeof(rupr), &cbReadSize);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read process parameters: %p", ntStatus);
			return {};
		}

		std::unique_ptr <wchar_t[]> buffer(new (std::nothrow) wchar_t[rupr.CommandLine.MaximumLength * sizeof(wchar_t)]);
		if (!IS_VALID_SMART_PTR(buffer))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for process parameters");
			return {};
		}
		
		ntStatus = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, rupr.CurrentDirectory.DosPath.Buffer, buffer.get(), rupr.CurrentDirectory.DosPath.Length, &cbReadSize);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read current path: %p", ntStatus);
			return {};
		}
		buffer.get()[rupr.CurrentDirectory.DosPath.Length / 2] = 0;

		return stdext::to_lower_wide(buffer.get());
	}
	std::wstring CProcess::GetCommandLine() const
	{
		const auto peb = this->GetPEB<PPEB>();
		if (!peb)
			return {};
		
		if (!peb->ProcessParameters)
			return {};

		// Read the process parameters
		RTL_USER_PROCESS_PARAMETERS rupr{ 0 };
		auto ntStatus = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, peb->ProcessParameters, &rupr, sizeof(rupr), nullptr);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read process parameters: %p", ntStatus);
			return {};
		}
		
		std::unique_ptr <wchar_t[]> buffer(new (std::nothrow) wchar_t[rupr.CommandLine.MaximumLength * sizeof(wchar_t)]);
		if (!IS_VALID_SMART_PTR(buffer))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for process parameters");
			return {};
		}
		
		// Get the command line
		SIZE_T cbReadSize = 0;
		ntStatus = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, rupr.CommandLine.Buffer, buffer.get(), rupr.CommandLine.Length, &cbReadSize);
		if (!NT_SUCCESS(ntStatus) || !cbReadSize || cbReadSize < rupr.CurrentDirectory.DosPath.Length)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to read process commandline: %p", ntStatus);
			return {};
		}
		buffer.get()[rupr.CurrentDirectory.DosPath.Length / 2] = 0;

		return std::wstring(buffer.get(), rupr.CommandLine.Length / 2);
	}
	bool CProcess::QueryDigitalSignature(SSignatureContext& ctx) const
	{
		const auto wstFileName = this->GetFullName();
		if (wstFileName.empty())
			return false;

		std::vector <SCertContext> vecCerts;
		const auto obHasEmbeddedSign = FileVerifier::GetEmbeddedCertificates(wstFileName, vecCerts);
		if (!obHasEmbeddedSign.has_value() || !obHasEmbeddedSign.value())
			return false;
		
		ctx.bVerified = PeSignatureVerifier::CheckFileSignature(wstFileName, true) == S_OK; // TODO: convertSignInfo(lRetVal)
		if (ctx.bVerified)
		{
			ctx.vecSignatures = std::move(vecCerts);
			return true;
		}

		return false;
	}
	bool CProcess::QueryFileVersion(SVersionContext& ctx) const
	{
		const auto wstFileName = this->GetFullName();
		if (wstFileName.empty())
			return false;

		CFileVersion ver;
		if (!ver.QueryFile(wstFileName))
			return false;

		ctx.stCompanyName = ver.GetCompanyName();
		ctx.stFileDescription = ver.GetFileDescription();
		ctx.stFileVersion = ver.GetFileVersion();
		ctx.stProductName = ver.GetProductName();
		ctx.stProductVersion = ver.GetProductVersion();
		return true;
	}
	std::wstring CProcess::GetProcessSID()
	{
		auto pInfo = this->__GetProcessInformation(TokenUser);
		
		HLOCAL sTmp;
		if (!g_winAPIs->ConvertSidToStringSidW(PTOKEN_USER(pInfo.data())->User.Sid, (LPWSTR*)&sTmp))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to convert SID to string");
			return {};
		}
		return (wchar_t*)sTmp;
	}
	std::wstring CProcess::GetProcessOwner()
	{
		HANDLE hToken = nullptr;
		if (!g_winAPIs->OpenProcessToken(m_hProcessUser, TOKEN_QUERY, &hToken))
		{
			APP_TRACE_LOG(LL_ERR, L"Open process token failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		DWORD dwSize{ 0 };
		g_winAPIs->GetTokenInformation(hToken, TokenOwner, nullptr, dwSize, &dwSize);
		if (dwSize == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"Get token information failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		SafeGlobal owner{ g_winAPIs->GlobalAlloc(GPTR, dwSize) };
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);
		if (owner == nullptr)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for token owner");
			return {};
		}
		if (!g_winAPIs->GetTokenInformation(hToken, TokenOwner, owner, dwSize, &dwSize))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get token owner with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		g_winAPIs->LookupAccountSidW(nullptr, ((TOKEN_OWNER*)owner.get())->Owner, nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);
		Domain = std::vector<WCHAR>(dwDomainLen);
		Name = std::vector<WCHAR>(dwNameLen);

		if (!g_winAPIs->LookupAccountSidW(nullptr, ((TOKEN_OWNER*)owner.get())->Owner, Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to lookup account with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		return std::wstring(Domain.data()) + xorstr_(L"\\") + std::wstring(Name.data());
	}
	std::wstring CProcess::GetProcessUserName()
	{
		HANDLE hToken = nullptr;
		if (!g_winAPIs->OpenProcessToken(m_hProcessUser, TOKEN_QUERY, &hToken))
		{
			APP_TRACE_LOG(LL_ERR, L"Open process token failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		DWORD dwSize = 0;
		g_winAPIs->GetTokenInformation(hToken, TokenUser, nullptr, dwSize, &dwSize);
		if (dwSize == 0)
		{
			APP_TRACE_LOG(LL_ERR, L"Get token information failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		SafeGlobal userToken{ g_winAPIs->GlobalAlloc(GPTR, dwSize) };
		if (!IS_VALID_SMART_PTR(userToken))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for token user with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		if (!g_winAPIs->GetTokenInformation(hToken, TokenUser, userToken, dwSize, &dwSize))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get token user with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		DWORD dwDomainLen = 0;
		DWORD dwNameLen = 0;
		SID_NAME_USE SIDType = SidTypeUnknown;
		g_winAPIs->LookupAccountSidW(nullptr, ((TOKEN_USER*)userToken.get())->User.Sid, nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);
		if (!g_winAPIs->LookupAccountSidW(nullptr, ((TOKEN_USER*)userToken.get())->User.Sid, Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType))
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to lookup account with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		std::wstring userName = std::wstring(Domain.data()) + xorstr_(L"\\") + std::wstring(Name.data());
//		std::wcout << L"Process user (logon) name: " << userName << std::endl;
		return userName;
	}
	bool CProcess::IsProcessElevated()
	{
		auto pInfo = this->__GetProcessInformation(TokenElevation);
		if (!pInfo.empty())
			return PTOKEN_ELEVATION(pInfo.data())->TokenIsElevated != 0;
		return false;
	}
	DWORD CProcess::GetProcessIntegrityLevel()
	{
		auto pInfo = this->__GetProcessInformation(TokenIntegrityLevel);
		if (pInfo.empty())
			return SECURITY_MANDATORY_UNTRUSTED_RID;
			
		const auto pTokenIL = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(pInfo.data());

		const auto dwAuthCount = static_cast<DWORD>(*g_winAPIs->GetSidSubAuthorityCount(pTokenIL->Label.Sid) - 1);
		if (!dwAuthCount)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get SID subauthority count");
			return SECURITY_MANDATORY_UNTRUSTED_RID;
		}

		const auto pdwIntegrityRet = g_winAPIs->GetSidSubAuthority(pTokenIL->Label.Sid, dwAuthCount);
		if (!pdwIntegrityRet)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get SID subauthority");
			return SECURITY_MANDATORY_UNTRUSTED_RID;
		}

		return *pdwIntegrityRet;
	}
	std::vector <std::wstring> CProcess::GetprocessIconDumps()
	{
		auto fnGetFileContentBase64Encoded = [](const std::wstring& wstFileName) -> std::wstring {
			SafeHandle pkFile = g_winAPIs->CreateFileW(
				wstFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr
			);
			if (!pkFile.IsValid())
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to open file: %s with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
				return {};
			}

			const auto dwFileSize = g_winAPIs->GetFileSize(pkFile.get(), nullptr);
			if (!dwFileSize || dwFileSize == INVALID_FILE_SIZE)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to get file size of file: %s with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
				return {};
			}

			std::vector <uint8_t> vecFileContent(dwFileSize);
			
			DWORD dwBytesRead = 0;
			if (!g_winAPIs->ReadFile(pkFile.get(), vecFileContent.data(), dwFileSize, &dwBytesRead, nullptr))
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to read file: %s with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
				return {};
			}
			else if (dwBytesRead != dwFileSize)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to read file: %s with error: %u", wstFileName.c_str(), g_winAPIs->GetLastError());
				return {};
			}

			return NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->EncodeBase64(vecFileContent.data(), dwFileSize);
		};
		
		auto vIconList = std::vector<std::wstring>();

		const auto wstName = this->GetFullName();
		if (wstName.empty())
			return vIconList;
		
		HICON hIconLarge = nullptr, hIconSmall = nullptr;
		const auto nIconCount = g_winAPIs->ExtractIconExW(wstName.c_str(), -1, NULL, NULL, 0);
		if (!nIconCount)
			return vIconList;
		
		for (auto i = 0u; i < nIconCount; i++)
		{
			if (g_winAPIs->ExtractIconExW(wstName.c_str(), i, &hIconLarge, &hIconSmall, 1) == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"ExtractIconExW(%u) fail! Error: %u", i, g_winAPIs->GetLastError());
				continue;
			}

			const auto wstTempFile = NoMercyCore::CApplication::Instance().DirFunctionsInstance()->CreateTempFileName(xorstr_(L"nmic"));
			if (wstTempFile.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to create temp filename");
				
				g_winAPIs->DestroyIcon(hIconLarge);
				g_winAPIs->DestroyIcon(hIconSmall);
				continue;
			}
			APP_TRACE_LOG(LL_SYS, L"Temp filename created! File: %s", wstTempFile.c_str());

			const auto wstBuffer = fnGetFileContentBase64Encoded(wstTempFile);
			APP_TRACE_LOG(LL_SYS, L"File encode result size: %u", wstBuffer.size());

			g_winAPIs->DestroyIcon(hIconLarge);
			g_winAPIs->DestroyIcon(hIconSmall);
			g_winAPIs->DeleteFileW(wstTempFile.c_str());
			
			vIconList.emplace_back(wstBuffer);
		}

		return vIconList;
	}
	double CProcess::GetCpuUsage()
	{
		FILETIME createTime, exitTime, kernelTime, userTime;
		if (!g_winAPIs->GetProcessTimes(m_hProcessUser, &createTime, &exitTime, &kernelTime, &userTime))
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcessTimes failed with error: %u", g_winAPIs->GetLastError());
			return -1.0;
		}

		const auto dwKernelTime = (static_cast <uint64_t> (kernelTime.dwHighDateTime) << 32) | kernelTime.dwLowDateTime;
		const auto dwUserTime = (static_cast <uint64_t> (userTime.dwHighDateTime) << 32) | userTime.dwLowDateTime;
		const auto dwTotalTime = dwKernelTime + dwUserTime;
		return static_cast <double> (dwTotalTime) / 1000.0;
	}
	double CProcess::GetMemoryUsage()
	{
		if (!g_winAPIs->GetPhysicallyInstalledSystemMemory)
			return {};

		PROCESS_MEMORY_COUNTERS_EX pmc;
		if (!g_winAPIs->GetProcessMemoryInfo(m_hProcessUser, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc)))
		{
			APP_TRACE_LOG(LL_ERR, L"GetProcessMemoryInfo failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		SIZE_T physicalMemoryUsed = pmc.WorkingSetSize;
		ULONGLONG physicalMemoryTotal = 0;
		if (!g_winAPIs->GetPhysicallyInstalledSystemMemory(&physicalMemoryTotal))
		{
			APP_TRACE_LOG(LL_ERR, L"GetPhysicallyInstalledSystemMemory failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		const auto memoryUsagePercent = static_cast<double>(physicalMemoryUsed) / physicalMemoryTotal * 100.0;
		return memoryUsagePercent;
	}
	std::wstring CProcess::GetProtectionStatus()
	{
		PS_PROTECTION psProtection{};
		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessProtectionInformation, &psProtection, sizeof(psProtection), nullptr);
		if (ntStatus != STATUS_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		std::wstring wstProtectionStatus;
		
		switch (psProtection.Type)
		{
		case PsProtectedTypeNone:
			wstProtectionStatus = xorstr_(L"None");
			break;
		case PsProtectedTypeProtectedLight:
			wstProtectionStatus = xorstr_(L"ProtectedLight");
			break;
		case PsProtectedTypeProtected:
			wstProtectionStatus = xorstr_(L"Protected");
			break;
		default:
			wstProtectionStatus = xorstr_(L"Unknown");
			break;
		}
		
		switch (psProtection.Signer)
		{
		case PsProtectedSignerNone:
			wstProtectionStatus += xorstr_(L"None");
			break;
		case PsProtectedSignerAuthenticode:
			wstProtectionStatus += xorstr_(L"Authenticode");
			break;
		case PsProtectedSignerCodeGen:
			wstProtectionStatus += xorstr_(L"CodeGen");
			break;
		case PsProtectedSignerAntimalware:
			wstProtectionStatus += xorstr_(L"Antimalware");
			break;
		case PsProtectedSignerLsa:
			wstProtectionStatus += xorstr_(L"Lsa");
			break;
		case PsProtectedSignerWindows:
			wstProtectionStatus += xorstr_(L"Windows");
			break;
		case PsProtectedSignerWinTcb:
			wstProtectionStatus += xorstr_(L"WinTcb");
			break;
		case PsProtectedSignerWinSystem:
			wstProtectionStatus += xorstr_(L"WinSystem");
			break;
		case PsProtectedSignerApp:
			wstProtectionStatus += xorstr_(L"App");
			break;
		default:
			wstProtectionStatus += xorstr_(L"Unknown");
			break;
		}

		return wstProtectionStatus;
	}
	bool CProcess::IsProtectedProcess()
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pebi{};
		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessBasicInformation, &pebi, sizeof(pebi), nullptr);
		if (ntStatus != STATUS_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		return pebi.IsProtectedProcess;
	}
	bool CProcess::IsSecureProcess()
	{
		PROCESS_EXTENDED_BASIC_INFORMATION pebi{};
		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessBasicInformation, &pebi, sizeof(pebi), nullptr);
		if (ntStatus != STATUS_SUCCESS)
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with error: %u", g_winAPIs->GetLastError());
			return {};
		}

		return pebi.IsSecureProcess;
	}
	ptr_t CProcess::GetPebAddress() const
	{
		if (m_nProcType == EProcessType::WOW64)
		{
			ULONG_PTR peb{ 0 };
			const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryInformationProcess(
				m_hProcessUser, ProcessWow64Information, &peb, sizeof(peb), nullptr
			);
			// const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessWow64Information, &peb, sizeof(peb), nullptr);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with status: %p", ntStatus);
				return nullptr;
			}
			return PtrToPtr64((void*)peb);
		}
		else
		{
			PROCESS_BASIC_INFORMATION pbi{};
			const auto ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryInformationProcess(
				m_hProcessUser, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr
			);
			// const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess failed with status: %p", ntStatus);
				return nullptr;
			}
			return pbi.PebBaseAddress;
		}
	}
	ptr_t CProcess::GetEProcessAddress()
	{
		if (m_nProcAccessType == EProcessAccessType::USER)
			return {};

		return {}; // TODO
	}
	ptr_t CProcess::GetInstrumentationCallback()
	{
		ULONG ReturnLength = 0;
		PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION CallbackInfo{};
		const auto ntStatus = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessInstrumentationCallback, &CallbackInfo, sizeof(CallbackInfo), &ReturnLength);
		return NT_SUCCESS(ntStatus) ? CallbackInfo.Callback : nullptr;
	};
	DWORD CProcess::GetParentConsolePID()
	{
		// todo
		return {};
	}
	std::wstring CProcess::GetPermissions()
	{
		// serialized json
		return {};
	}
	bool CProcess::GetMandatoryPolicy(PACCESS_MASK Mask)
	{
		auto bRet = false;
		PSECURITY_DESCRIPTOR pkCurrSecDesc = nullptr;

		do
		{
			ULONG cbBufferSize = 0x100;
			pkCurrSecDesc = reinterpret_cast<PSECURITY_DESCRIPTOR>(CMemHelper::Allocate(cbBufferSize));
			if (!pkCurrSecDesc)
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to allocate memory for security descriptor");
				break;
			}

			auto ntStatus = g_winAPIs->NtQuerySecurityObject(
				m_hProcessUser,
				LABEL_SECURITY_INFORMATION,
				pkCurrSecDesc,
				cbBufferSize,
				&cbBufferSize
			);
			if (ntStatus == STATUS_BUFFER_TOO_SMALL)
			{
				pkCurrSecDesc = CMemHelper::ReAlloc(pkCurrSecDesc, cbBufferSize);
				if (!pkCurrSecDesc)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to re-allocate memory for security descriptor");
					break;
				}

				ntStatus = g_winAPIs->NtQuerySecurityObject(
					m_hProcessUser,
					LABEL_SECURITY_INFORMATION,
					pkCurrSecDesc,
					cbBufferSize,
					&cbBufferSize
				);
			}
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQuerySecurityObject failed with status: %p", ntStatus);
				break;
			}

			PACL currentSacl;
			BOOLEAN currentSaclPresent;
			BOOLEAN currentSaclDefaulted;
			ntStatus = g_winAPIs->RtlGetSaclSecurityDescriptor(
				pkCurrSecDesc,
				&currentSaclPresent,
				&currentSacl,
				&currentSaclDefaulted
			);
			if (!NT_SUCCESS(ntStatus))
			{
				APP_TRACE_LOG(LL_ERR, L"RtlGetSaclSecurityDescriptor failed with status: %p", ntStatus);
				break;
			}
			else if (!(currentSaclPresent && currentSacl))
			{
				APP_TRACE_LOG(LL_ERR, L"RtlGetSaclSecurityDescriptor status failed with status: %p", ntStatus);
				break;
			}

			for (USHORT i = 0; i < currentSacl->AceCount; i++)
			{
				PSYSTEM_MANDATORY_LABEL_ACE currentAce;
				ntStatus = g_winAPIs->RtlGetAce(currentSacl, i, (PVOID*)&currentAce);
				if (!NT_SUCCESS(ntStatus))
				{
					APP_TRACE_LOG(LL_ERR, L"RtlGetAce failed with status: %p", ntStatus);
					break;
				}

				if (currentAce->Header.AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE)
				{
					*Mask = currentAce->Mask;
					bRet = true;
					break;
				}
			}
		} while (FALSE);

		if (pkCurrSecDesc)
		{
			CMemHelper::Free(pkCurrSecDesc);
			pkCurrSecDesc = nullptr;
		}
		return bRet;
	}
	std::wstring CProcess::GetPerformanceStats()
	{
		// serialized json
		return {};
	}
	std::wstring CProcess::GetEnvironmentVariables()
	{
		// process, user, system
		// serialized json
		return {};
	}
	
	HANDLE CProcess::CreateThread(ptr_t lpStartAddress, ptr_t lpParameter) const
	{
		HANDLE hThread = 0;
		CLIENT_ID cid = { 0, 0 };

		const auto ntStatus = g_winAPIs->RtlCreateUserThread(m_hProcessUser, nullptr, 0, 0, 0, 0, (PUSER_THREAD_START_ROUTINE)Ptr64ToPtr(lpStartAddress), Ptr64ToPtr(lpParameter), &hThread, &cid);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlCreateUserThread failed with status: %p", ntStatus);
			return {};
		}

		return hThread;
	}
	bool CProcess::Terminate(DWORD dwExitCode) const
	{
		const auto ntStatus = g_winAPIs->NtTerminateProcess(m_hProcessUser, dwExitCode);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtTerminateProcess failed with status: %p", ntStatus);
			return false;
		}

		return true;
	}
	bool CProcess::Suspend() const
	{
		const auto ntStatus = g_winAPIs->NtSuspendProcess(m_hProcessUser);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtSuspendProcess failed with status: %p", ntStatus);
			return false;
		}

		return true;
	}
	bool CProcess::Resume() const
	{
		const auto ntStatus = g_winAPIs->NtResumeProcess(m_hProcessUser);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtResumeProcess failed with status: %p", ntStatus);
			return false;
		}

		return true;
	}
	bool CProcess::IsRunning() const
	{
		return CProcessFunctions::ProcessIsItAlive(m_dwProcessID);
	}

	template <typename T>
	T CProcess::GetPEB() const
	{
		const auto pPEB = GetPebAddress();
		if (!pPEB)
			return nullptr;

		if (std::is_same<T, PPEB32>::value)
		{
			PPEB32 pPEB32 = nullptr;
			if (!m_spMemoryHelper->Read(pPEB, &pPEB32, sizeof(pPEB32)))
			{
				APP_TRACE_LOG(LL_ERR, L"Read failed");
				return nullptr;
			}
			return (T)pPEB32;
		}
		else if (std::is_same<T, PPEB>::value)
		{
			PPEB pPEBptr = nullptr;
			if (!m_spMemoryHelper->Read(pPEB, &pPEBptr, sizeof(pPEBptr)))
			{
				APP_TRACE_LOG(LL_ERR, L"Read failed");
				return nullptr;
			}
			return pPEBptr;
		}
		else if (std::is_same<T, wow64pp::defs::PEB_64*>::value)
		{
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return nullptr;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return nullptr;
			}

			ULONG64 ul64ReadBytes = 0;
			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pPBI = { 0 };
			auto ntStat = g_winAPIs->NtWow64QueryInformationProcess64(m_hProcessUser, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"NtWow64QueryInformationProcess64(ProcessBasicInformation) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return nullptr;
			}

			wow64pp::defs::PEB_64* pPEBptr = nullptr;
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, m_hProcessUser, (PVOID64)pPBI.PebBaseAddress, &pPEBptr, sizeof(pPEBptr), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtReadVirtualMemory fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return nullptr;
			}
			
			return (T)pPEBptr;
		}
		else
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid type: %s", typeid(T).name());
			return nullptr;
		}
	}

	void CProcess::EnumerateThreads(std::function<bool(std::shared_ptr <CThread> thread)> fn)
	{
		const auto upThreadEnumerator = stdext::make_unique_nothrow<CThreadEnumeratorNT>(m_dwProcessID);
		if (!IS_VALID_SMART_PTR(upThreadEnumerator))
		{
			APP_TRACE_LOG(LL_ERR, L"upThreadEnumerator allocation failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		const auto systemThreadOwnerProcInfo = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(upThreadEnumerator->GetProcInfo());
		if (!systemThreadOwnerProcInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"systemThreadOwnerProcInfo is null! Last error: %u", g_winAPIs->GetLastError());
			return;
		}

		const auto dwThreadCount = upThreadEnumerator->GetThreadCount(systemThreadOwnerProcInfo);
		if (!dwThreadCount)
		{
			APP_TRACE_LOG(LL_ERR, L"dwThreadCount is null! Last error: %u", g_winAPIs->GetLastError());
			return;
		}

		auto pkThread = reinterpret_cast<SYSTEM_THREAD_INFORMATION*>(upThreadEnumerator->GetThreadList(systemThreadOwnerProcInfo));
		if (!pkThread)
		{
			APP_TRACE_LOG(LL_ERR, L"pk_Thread is null! Last error: %u", g_winAPIs->GetLastError());
			return;
		}

		for (std::size_t i = 0; i < dwThreadCount; i++)
		{
			const auto dwThreadId = HandleToULong(pkThread->ClientId.UniqueThread);
			if (!dwThreadId)
				continue;

			auto thread = stdext::make_shared_nothrow<CThread>(dwThreadId, THREAD_ALL_ACCESS, this);
			if (!IS_VALID_SMART_PTR(thread) || !thread->IsValid())
				continue;

			if (!fn(thread))
				break;
			
			pkThread++;
		}
	}
	auto CProcess::GetThreads()
	{
		std::vector <std::shared_ptr <CThread>> threads;
		EnumerateThreads([&](std::shared_ptr <CThread> thread) {
			threads.push_back(thread);
			return true;
		});
		return threads;
	}

	void CProcess::EnumerateModules(std::function<bool(std::shared_ptr <CModule> mdl)> fn)
	{
		struct SModuleEnumContext
		{
			ptr_t base;
			std::uint32_t size;
			std::wstring name;
		};
		auto vOutput = std::vector <std::shared_ptr <SModuleEnumContext>>();

		auto iterate_wow64 = [&] {
			auto x64_ntdll_handle = wow64pp::module_handle(xorstr_("ntdll.dll"));
			if (!x64_ntdll_handle)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_ntdll could not handled.");
				return;
			}

			auto x64_NtReadVirtualMemory = wow64pp::import(x64_ntdll_handle, xorstr_("NtReadVirtualMemory"));
			if (!x64_NtReadVirtualMemory)
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtReadVirtualMemory could not handled.");
				return;
			}

			NTSTATUS ntStat = 0;
			ULONG64 ul64ReadBytes = 0;

			wow64pp::defs::PROCESS_BASIC_INFORMATION_64 pPBI = { 0 };
			ntStat = g_winAPIs->NtWow64QueryInformationProcess64(m_hProcessUser, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"NtWow64QueryInformationProcess64(ProcessBasicInformation) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			wow64pp::defs::PEB_64 pPEB = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, m_hProcessUser, (PVOID64)pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_WARN, L"x64_NtReadVirtualMemory(1) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			if (!pPEB.Ldr)
			{
				APP_TRACE_LOG(LL_ERR, L"Peb Loader data is null!");
				return;
			}

			wow64pp::defs::PEB_LDR_DATA_64 pPebLdrData = { 0 };
			ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, m_hProcessUser, (PVOID64)pPEB.Ldr, &pPebLdrData, sizeof(pPebLdrData), &ul64ReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"x64_NtReadVirtualMemory(2) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			auto iModuleCount = 0;
			auto iRetryCount = 0;

			auto Head = pPebLdrData.InLoadOrderModuleList.Flink;
			auto Node = Head;

			// CHECKME: Infinite loop
			//Head -= sizeof(wow64pp::defs::LIST_ENTRY_64);

			do
			{
				wow64pp::defs::LDR_DATA_TABLE_ENTRY_64 pCurrModule = { 0 };
				ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, m_hProcessUser, (PVOID64)Node, &pCurrModule, sizeof(pCurrModule), &ul64ReadBytes);

				if (NT_SUCCESS(ntStat))
				{
					if (pCurrModule.DllBase)
					{
						++iModuleCount;

						WCHAR wstrModuleName[MAX_PATH] = { L'\0' };

						ntStat = wow64pp::call_function(x64_NtReadVirtualMemory, m_hProcessUser, (PVOID64)pCurrModule.FullDllName.Buffer, &wstrModuleName, pCurrModule.FullDllName.Length, &ul64ReadBytes);
						if (!NT_SUCCESS(ntStat))
						{
							APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(4) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
							continue;
						}

						auto spCurrModuleCtx = stdext::make_shared_nothrow<SModuleEnumContext>();
						if (!IS_VALID_SMART_PTR(spCurrModuleCtx))
						{
							APP_TRACE_LOG(LL_ERR, L"Module enum context container can NOT allocated! Error: %u", g_winAPIs->GetLastError());
							return;
						}

						spCurrModuleCtx->base = (ptr_t)pCurrModule.DllBase;
						spCurrModuleCtx->size = pCurrModule.SizeOfImage;
						spCurrModuleCtx->name = wstrModuleName;

						vOutput.push_back(spCurrModuleCtx);
					}
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(3) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
					if (++iRetryCount == 3)
					{
						break;
					}
				}

				Node = pCurrModule.InLoadOrderLinks.Flink;

			} while (Head != Node && iModuleCount < ENUM_PROCESS_MODULES_LIMIT);
		};

		auto iterate_native = [&] {
			NTSTATUS ntStat = 0;
			SIZE_T cbReadBytes = 0;

			PROCESS_BASIC_INFORMATION pPBI = { 0 };
			ntStat = g_winAPIs->NtQueryInformationProcess(m_hProcessUser, ProcessBasicInformation, &pPBI, sizeof(pPBI), NULL);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryInformationProcess(ProcessBasicInformation) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			PEB pPEB = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, pPBI.PebBaseAddress, &pPEB, sizeof(pPEB), &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_WARN, L"NtReadVirtualMemory(1) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			if (!pPEB.Ldr)
			{
				APP_TRACE_LOG(LL_ERR, L"Peb Loader data is null!");
				return;
			}

			PEB_LDR_DATA pPebLdrData = { 0 };
			ntStat = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, pPEB.Ldr, &pPebLdrData, sizeof(pPebLdrData), &cbReadBytes);
			if (!NT_SUCCESS(ntStat))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(2) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
				return;
			}

			auto iModuleCount = 0;
			auto iRetryCount = 0;

			auto Head = pPebLdrData.InLoadOrderModuleList.Flink;
			auto Node = Head;

			// CHECKME: Infinite loop
			//Head -= sizeof(LIST_ENTRY);

			do
			{
				LDR_DATA_TABLE_ENTRY pCurrModule = { 0 };
				ntStat = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, Node, &pCurrModule, sizeof(pCurrModule), &cbReadBytes);

				if (NT_SUCCESS(ntStat))
				{
					if (pCurrModule.DllBase)
					{
						++iModuleCount;

						WCHAR wstrModuleName[MAX_PATH] = { L'\0' };
						ntStat = g_winAPIs->NtReadVirtualMemory(m_hProcessUser, pCurrModule.FullDllName.Buffer, &wstrModuleName, pCurrModule.FullDllName.Length, &cbReadBytes);
						if (!NT_SUCCESS(ntStat))
						{
							APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(4) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
							continue;
						}

						auto spCurrModuleCtx = stdext::make_shared_nothrow<SModuleEnumContext>();
						if (!IS_VALID_SMART_PTR(spCurrModuleCtx))
						{
							APP_TRACE_LOG(LL_ERR, L"Module enum context container can NOT allocated! Error: %u", g_winAPIs->GetLastError());
							return;
						}

						spCurrModuleCtx->base = (ptr_t)pCurrModule.DllBase;
						spCurrModuleCtx->size = pCurrModule.SizeOfImage;
						spCurrModuleCtx->name = wstrModuleName;

						vOutput.push_back(spCurrModuleCtx);
					}
				}
				else
				{
					APP_TRACE_LOG(LL_ERR, L"ReadProcessMemory(3) fail! Target process: %p Status: %p", m_hProcessUser, ntStat);
					if (++iRetryCount == 3)
					{
						break;
					}
				}

				Node = pCurrModule.InLoadOrderLinks.Flink;

			} while (Head != Node && iModuleCount < ENUM_PROCESS_MODULES_LIMIT);
		};

		//if (m_nProcType == EProcessType::WOW64)
		if (stdext::is_wow64())
			iterate_wow64();
		else
			iterate_native();

		for (const auto& mdl : vOutput)
		{
			auto module_ = stdext::make_shared_nothrow<CModule>(this, mdl->base, mdl->size, mdl->name);
			if (!IS_VALID_SMART_PTR(module_) || !module_->IsValid())
				continue;

			if (!fn(module_))
				break;
		}
		
		vOutput.clear();
	}
	auto CProcess::GetModules()
	{
		std::vector <std::shared_ptr <CModule>> vOutput;
		EnumerateModules([&](std::shared_ptr <CModule> module_) {
			vOutput.push_back(module_);
			return true;
		});
		return vOutput;
	}

	void CProcess::EnumerateSections(std::function<bool(std::shared_ptr <CSection> section)> fn)
	{
		struct SSectionEnumContext
		{
			ptr_t		BaseAddress{ nullptr };
			ptr_t		AllocationBase{ nullptr };
			std::size_t	RegionSize{ 0 };
		};
		auto vOutput = std::vector<std::shared_ptr<SSectionEnumContext>>();
				
		auto dwSectionCount = 0UL;
		MEMORY_BASIC_INFORMATION64 mbi{ 0 };
		auto ntStatus = 0UL;
		auto lastBase = 0ULL;

		for (ULONGLONG memptr = MEMORY_START_ADDRESS;
			 memptr < (m_nProcType == EProcessType::NATIVE_64) ? MEMORY_END_ADDRESS_X64 : MEMORY_END_ADDRESS_X86;
			 memptr = mbi.BaseAddress + mbi.RegionSize)
		{
			ntStatus = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->QueryVirtualMemory(
				m_hProcessUser, (PVOID64)memptr, MemoryBasicInformation, &mbi, sizeof(mbi)
			);

			if (ntStatus == STATUS_INVALID_PARAMETER || ntStatus == STATUS_ACCESS_DENIED || ntStatus == STATUS_PROCESS_IS_TERMINATING)
				break;
			else if (ntStatus != STATUS_SUCCESS)
				continue;

			// Filter non-section regions
			if (mbi.State != MEM_COMMIT /* || mbi.Type != MEM_IMAGE || lastBase == mbi.AllocationBase */)
				continue;
			
			auto spCurrSectionCtx = stdext::make_shared_nothrow<SSectionEnumContext>();
			if (IS_VALID_SMART_PTR(spCurrSectionCtx))
			{
				spCurrSectionCtx->BaseAddress = (ptr_t)(mbi.BaseAddress);
				spCurrSectionCtx->AllocationBase = (ptr_t)(mbi.AllocationBase);
				spCurrSectionCtx->RegionSize = mbi.RegionSize;

				vOutput.emplace_back(spCurrSectionCtx);
				dwSectionCount++;
			}

			lastBase = mbi.AllocationBase;
		}

		if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_INVALID_PARAMETER)
		{
			APP_TRACE_LOG(LL_ERR, L"NtQueryVirtualMemory failed with status: %p", ntStatus);
		}

		for (const auto& sec : vOutput)
		{
			auto section_ = stdext::make_shared_nothrow<CSection>(this, sec->BaseAddress, sec->AllocationBase, sec->RegionSize);
			if (!IS_VALID_SMART_PTR(section_) || !section_->IsValid())
				continue;

			if (!fn(section_))
				break;

			g_winAPIs->Sleep(1);
		}
		
		vOutput.clear();
	}
	auto CProcess::GetSections()
	{
		std::vector <std::shared_ptr <CSection>> vOutput;
		EnumerateSections([&](std::shared_ptr <CSection> section_) {
			vOutput.push_back(section_);
			return true;
		});
		return vOutput;
	}

	void CProcess::EnumerateHandles(std::function<bool(std::shared_ptr <CHandle> handle)> fn)
	{
		struct SHandleScanContext
		{
			HANDLE hHandle{ nullptr };
			PVOID pObject{ nullptr };
			USHORT uTypeIndex{ 0 };
			DWORD dwGrantedAccess{ 0 };
		};

		auto dwHandleInfoSize = 2000;
		auto ntStat = NTSTATUS(0x0);

		auto lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)CMemHelper::Allocate(dwHandleInfoSize);
		if (!lpHandleInfo)
		{
			APP_TRACE_LOG(LL_ERR, L"lpHandleInfo allocation failed with error: %u", g_winAPIs->GetLastError());
			return;
		}

		while ((ntStat = g_winAPIs->NtQuerySystemInformation(SystemExtendedHandleInformation, lpHandleInfo, dwHandleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			dwHandleInfoSize *= 2;
			lpHandleInfo = (PSYSTEM_HANDLE_INFORMATION_EX)CMemHelper::ReAlloc(lpHandleInfo, dwHandleInfoSize);
		}

		if (!NT_SUCCESS(ntStat))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQuerySystemInformation failed with error: %p", ntStat);
			CMemHelper::Free(lpHandleInfo);
			return;
		}

		for (std::size_t i = 0; i < lpHandleInfo->NumberOfHandles; i++)
		{
			const auto pkCurrHandle = lpHandleInfo->Handles[i];
			
			if (pkCurrHandle.UniqueProcessId == m_dwProcessID)
			{
				auto handle_ = stdext::make_shared_nothrow<CHandle>(
					this,
					(HANDLE)pkCurrHandle.HandleValue,
					pkCurrHandle.Object,
					pkCurrHandle.ObjectTypeIndex,
					pkCurrHandle.GrantedAccess
				);
				if (!IS_VALID_SMART_PTR(handle_) || !handle_->IsValid())
					continue;

				if (!fn(handle_))
					break;
			}
		}

		CMemHelper::Free(lpHandleInfo);
	}
	auto CProcess::GetHandles()
	{
		std::vector <std::shared_ptr <CHandle>> vOutput;
		EnumerateHandles([&](std::shared_ptr <CHandle> handle_) {
			vOutput.push_back(handle_);
			return true;
		});
		return vOutput;
	}

	std::map <std::wstring, std::wstring> CProcess::GetMitigationPolicies()
	{
		std::map <std::wstring, std::wstring> mapMitigationPolicies;
		
		if (!IsWindows8OrGreater())
			return {};

		PROCESS_MITIGATION_DEP_POLICY depPolicy{ 0 };
		auto bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessDEPPolicy, &depPolicy, sizeof(depPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"DEP_ENABLED"), std::to_wstring(depPolicy.Enable));
			mapMitigationPolicies.emplace(xorstr_(L"DEP_PERMANENT"), std::to_wstring(depPolicy.Permanent));
			mapMitigationPolicies.emplace(xorstr_(L"DEP_FLAGS"), std::to_wstring(depPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"DEP_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_ASLR_POLICY aslrPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessASLRPolicy, &aslrPolicy, sizeof(aslrPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_ENABLE_BUR"), std::to_wstring(aslrPolicy.EnableBottomUpRandomization));
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_FORCE_RELOCATE"), std::to_wstring(aslrPolicy.EnableForceRelocateImages));
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_HIGH_ENTROPY"), std::to_wstring(aslrPolicy.EnableHighEntropy));
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_DISALLOW_STRIPPED"), std::to_wstring(aslrPolicy.DisallowStrippedImages));
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_FLAGS"), std::to_wstring(aslrPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"ASLR_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_DYNAMIC_CODE_POLICY dynamicCodePolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessDynamicCodePolicy, &dynamicCodePolicy, sizeof(dynamicCodePolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_PROHIBIT_DYN_CODE"), std::to_wstring(dynamicCodePolicy.ProhibitDynamicCode));
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_ALLOW_THREAD_OPT_OUT"), std::to_wstring(dynamicCodePolicy.AllowThreadOptOut));
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_ALLOW_REMOTE_DOWNGRADE"), std::to_wstring(dynamicCodePolicy.AllowRemoteDowngrade));
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_AUDIT_PROHIBIT_DYN_CODE"), std::to_wstring(dynamicCodePolicy.AuditProhibitDynamicCode));
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_FLAGS"), std::to_wstring(dynamicCodePolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"DYNAMIC_CODE_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_STRICT_HANDLE_CHECK_POLICY strictHandlePolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessStrictHandleCheckPolicy, &strictHandlePolicy, sizeof(strictHandlePolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"STRICT_HANDLE_CHECK_RAISE_EXC"), std::to_wstring(strictHandlePolicy.RaiseExceptionOnInvalidHandleReference));
			mapMitigationPolicies.emplace(xorstr_(L"STRICT_HANDLE_CHECK_ENABLE_HANDLE_EXC"), std::to_wstring(strictHandlePolicy.HandleExceptionsPermanentlyEnabled));
			mapMitigationPolicies.emplace(xorstr_(L"STRICT_HANDLE_CHECK_FLAGS"), std::to_wstring(strictHandlePolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"STRICT_HANDLE_CHECK_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_SYSTEM_CALL_DISABLE_POLICY syscallDisablePolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessSystemCallDisablePolicy, &syscallDisablePolicy, sizeof(syscallDisablePolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"SYSCALL_DISABLE_DISALLOW_WIN32K"), std::to_wstring(syscallDisablePolicy.DisallowWin32kSystemCalls));
			mapMitigationPolicies.emplace(xorstr_(L"SYSCALL_DISABLE_AUDIT_WIN32K"), std::to_wstring(syscallDisablePolicy.AuditDisallowWin32kSystemCalls));
			mapMitigationPolicies.emplace(xorstr_(L"SYSCALL_DISABLE_FLAGS"), std::to_wstring(syscallDisablePolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"SYSCALL_DISABLE_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY extensionPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessExtensionPointDisablePolicy, &extensionPolicy, sizeof(extensionPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"EXTENSION_POINT_DISABLE_EXT_PTS"), std::to_wstring(extensionPolicy.DisableExtensionPoints));
			mapMitigationPolicies.emplace(xorstr_(L"EXTENSION_POINT_DISABLE_FLAGS"), std::to_wstring(extensionPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"EXTENSION_POINT_DISABLE_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_CONTROL_FLOW_GUARD_POLICY cfgPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessControlFlowGuardPolicy, &cfgPolicy, sizeof(cfgPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_ENABLE"), std::to_wstring(cfgPolicy.EnableControlFlowGuard));
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_ENABLE_EXP_SUPP"), std::to_wstring(cfgPolicy.EnableExportSuppression));
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_STRICT_MODE"), std::to_wstring(cfgPolicy.StrictMode));
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_ENABLE_XFG"), std::to_wstring(cfgPolicy.EnableControlFlowGuard));
			//				mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_ENABLE_XFG_AUDIT_MODE"), std::to_wstring(cfgPolicy.EnableXfgAuditMode));
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_FLAGS"), std::to_wstring(cfgPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"CONTROL_FLOW_GUARD_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY signaturePolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessSignaturePolicy, &signaturePolicy, sizeof(signaturePolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_MS_SIGN_ONLY"), std::to_wstring(signaturePolicy.MicrosoftSignedOnly));
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_STORE_SIGN_ONLY"), std::to_wstring(signaturePolicy.StoreSignedOnly));
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_MITIGATION_OPT_IN"), std::to_wstring(signaturePolicy.MitigationOptIn));
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_MS_SIGN_ONLY_AUDIT"), std::to_wstring(signaturePolicy.AuditMicrosoftSignedOnly));
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_STORE_SIGN_ONLY_AUDIT"), std::to_wstring(signaturePolicy.AuditStoreSignedOnly));
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_FLAGS"), std::to_wstring(signaturePolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"BINARY_SIGNATURE_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_FONT_DISABLE_POLICY fontPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessFontDisablePolicy, &fontPolicy, sizeof(fontPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"FONT_DISABLE_DISABLE_NON_SYSTEM"), std::to_wstring(fontPolicy.DisableNonSystemFonts));
			mapMitigationPolicies.emplace(xorstr_(L"FONT_DISABLE_DISABLE_AUDIT"), std::to_wstring(fontPolicy.AuditNonSystemFontLoading));
			mapMitigationPolicies.emplace(xorstr_(L"FONT_DISABLE_FLAGS"), std::to_wstring(fontPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"FONT_DISABLE_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_IMAGE_LOAD_POLICY imageLoadPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessImageLoadPolicy, &imageLoadPolicy, sizeof(imageLoadPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_NO_REMOTE_IMAGE"), std::to_wstring(imageLoadPolicy.NoRemoteImages));
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_NO_LOW_MANDATORY_LABEL_IMAGE"), std::to_wstring(imageLoadPolicy.NoLowMandatoryLabelImages));
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_PREFER_SYSTEM32_IMAGES"), std::to_wstring(imageLoadPolicy.PreferSystem32Images));
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_AUDIT_NO_REMOTE_IMAGE"), std::to_wstring(imageLoadPolicy.AuditNoRemoteImages));
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_AUDIT_NO_LOW_MANDATORY_LABEL_IMAGE"), std::to_wstring(imageLoadPolicy.AuditNoLowMandatoryLabelImages));
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_IMAGE_LOAD_POLICY_FLAGS"), std::to_wstring(imageLoadPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"IMAGE_LOAD_LIMIT_IMAGE_LOAD_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_SYSTEM_CALL_FILTER_POLICY systemCallFilterPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessSystemCallFilterPolicy, &systemCallFilterPolicy, sizeof(systemCallFilterPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"SYSTEM_CALL_FILTER_POLICY_FILTER"), std::to_wstring(systemCallFilterPolicy.FilterId));
			mapMitigationPolicies.emplace(xorstr_(L"SYSTEM_CALL_FILTER_POLICY_FLAGS"), std::to_wstring(systemCallFilterPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"SYSTEM_CALL_FILTER_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_PAYLOAD_RESTRICTION_POLICY payloadRestrictionPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessPayloadRestrictionPolicy, &payloadRestrictionPolicy, sizeof(payloadRestrictionPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_EXPORT_ADDRESS_FILTER"), std::to_wstring(payloadRestrictionPolicy.EnableExportAddressFilter));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_EXPORT_ADDRESS_FILTER"), std::to_wstring(payloadRestrictionPolicy.AuditExportAddressFilter));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_EXPORT_ADDRESS_FILTER_PLUS"), std::to_wstring(payloadRestrictionPolicy.EnableExportAddressFilterPlus));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_EXPORT_ADDRESS_FILTER_PLUS"), std::to_wstring(payloadRestrictionPolicy.AuditExportAddressFilterPlus));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_IMPORT_ADDRESS_FILTER"), std::to_wstring(payloadRestrictionPolicy.EnableImportAddressFilter));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_IMPORT_ADDRESS_FILTER"), std::to_wstring(payloadRestrictionPolicy.AuditImportAddressFilter));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_ROP_STACK_PIVOT"), std::to_wstring(payloadRestrictionPolicy.EnableRopStackPivot));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_ROP_STACK_PIVOT"), std::to_wstring(payloadRestrictionPolicy.AuditRopStackPivot));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_ROP_CALLER_CHECK"), std::to_wstring(payloadRestrictionPolicy.EnableRopCallerCheck));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_ROP_CALLER_CHECK"), std::to_wstring(payloadRestrictionPolicy.AuditRopCallerCheck));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_ENABLE_ROP_SIM_EXEC"), std::to_wstring(payloadRestrictionPolicy.EnableRopSimExec));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_AUDIT_ROP_SIM_EXEC"), std::to_wstring(payloadRestrictionPolicy.AuditRopSimExec));
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY_FLAGS"), std::to_wstring(payloadRestrictionPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"PAYLOAD_RESTRICTION_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_CHILD_PROCESS_POLICY childProcPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessChildProcessPolicy, &childProcPolicy, sizeof(childProcPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"CHILD_PROCESS_POLICY_NO_CHILD_PROCESS_CREATION"), std::to_wstring(childProcPolicy.NoChildProcessCreation));
			mapMitigationPolicies.emplace(xorstr_(L"CHILD_PROCESS_POLICY_AUDIT_NO_CHILD_PROCESS_CREATION"), std::to_wstring(childProcPolicy.AuditNoChildProcessCreation));
			mapMitigationPolicies.emplace(xorstr_(L"CHILD_PROCESS_POLICY_ALLOW_SECURE_PROCESS_CREATION"), std::to_wstring(childProcPolicy.AllowSecureProcessCreation));
			mapMitigationPolicies.emplace(xorstr_(L"CHILD_PROCESS_POLICY_FLAGS"), std::to_wstring(childProcPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"CHILD_PROCESS_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_SIDE_CHANNEL_ISOLATION_POLICY sideChannelIsolationPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessSideChannelIsolationPolicy, &sideChannelIsolationPolicy, sizeof(sideChannelIsolationPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY_SMT_BRANCH_TARGET_ISOLATION"), std::to_wstring(sideChannelIsolationPolicy.SmtBranchTargetIsolation));
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY_ISOLATE_SECURITY_DOMAIN"), std::to_wstring(sideChannelIsolationPolicy.IsolateSecurityDomain));
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY_DISABLE_PAGE_COMBINE"), std::to_wstring(sideChannelIsolationPolicy.DisablePageCombine));
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY_SPECULATIVE_STORE_BYPASS_DISABLE"), std::to_wstring(sideChannelIsolationPolicy.SpeculativeStoreBypassDisable));
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY_FLAGS"), std::to_wstring(sideChannelIsolationPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"SIDE_CHANNEL_ISOLATION_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY userShadowStackPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessUserShadowStackPolicy, &userShadowStackPolicy, sizeof(userShadowStackPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_ENABLE_USER_SHADOW_STACK"), std::to_wstring(userShadowStackPolicy.EnableUserShadowStack));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_AUDIT_USER_SHADOW_STACK"), std::to_wstring(userShadowStackPolicy.AuditUserShadowStack));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_SET_CONTEXT_IP_VALIDATION"), std::to_wstring(userShadowStackPolicy.SetContextIpValidation));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_AUDIT_SET_CONTEXT_IP_VALIDATION"), std::to_wstring(userShadowStackPolicy.AuditSetContextIpValidation));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_ENABLE_USER_SHADOW_STACK_STRICT_MODE"), std::to_wstring(userShadowStackPolicy.EnableUserShadowStackStrictMode));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_BLOCK_NON_CET_BINARIES"), std::to_wstring(userShadowStackPolicy.BlockNonCetBinaries));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_BLOCK_NON_CET_BINARIES_NON_EHCONT"), std::to_wstring(userShadowStackPolicy.BlockNonCetBinariesNonEhcont));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_AUDIT_BLOCK_NON_CET_BINARIES"), std::to_wstring(userShadowStackPolicy.AuditBlockNonCetBinaries));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_CET_DYNAMIC_APIS_OUT_OF_PROC_ONLY"), std::to_wstring(userShadowStackPolicy.CetDynamicApisOutOfProcOnly));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_SET_CONTEXT_IP_VALIDATION_RELAXED_MODE"), std::to_wstring(userShadowStackPolicy.SetContextIpValidationRelaxedMode));
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY_FLAGS"), std::to_wstring(userShadowStackPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"USER_SHADOW_STACK_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		/*
		PROCESS_MITIGATION_REDIRECTION_TRUST_POLICY redirectTrustPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessRedirectionTrustPolicy, &redirectTrustPolicy, sizeof(redirectTrustPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"REDIRECTION_TRUST_POLICY_ENFORCE"), std::to_wstring(redirectTrustPolicy.EnforceRedirectionTrust));
			mapMitigationPolicies.emplace(xorstr_(L"REDIRECTION_TRUST_POLICY_AUDIT"), std::to_wstring(redirectTrustPolicy.AuditRedirectionTrust));
			mapMitigationPolicies.emplace(xorstr_(L"REDIRECTION_TRUST_POLICY_FLAGS"), std::to_wstring(redirectTrustPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"REDIRECTION_TRUST_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_USER_POINTER_AUTH_POLICY userPointerAuthPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessUserPointerAuthPolicy, &userPointerAuthPolicy, sizeof(userPointerAuthPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"USER_POINTER_AUTH_POLICY_ENABLE"), std::to_wstring(userPointerAuthPolicy.EnablePointerAuthUserIp));
			mapMitigationPolicies.emplace(xorstr_(L"USER_POINTER_AUTH_POLICY_FLAGS"), std::to_wstring(userPointerAuthPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"USER_POINTER_AUTH_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}

		PROCESS_MITIGATION_SEHOP_POLICY sehopPolicy{ 0 };
		bPolicyRet = g_winAPIs->GetProcessMitigationPolicy(m_hProcessUser, ProcessSEHOPPolicy, &sehopPolicy, sizeof(sehopPolicy));
		if (bPolicyRet)
		{
			mapMitigationPolicies.emplace(xorstr_(L"SEHOP_POLICY_ENABLE"), std::to_wstring(sehopPolicy.EnableSehop));
			mapMitigationPolicies.emplace(xorstr_(L"SEHOP_POLICY_FLAGS"), std::to_wstring(sehopPolicy.Flags));
		}
		else
		{
			mapMitigationPolicies.emplace(xorstr_(L"SEHOP_POLICY"), fmt::format(xorstr_(L"FAILED_{0}"), g_winAPIs->GetLastError()));
		}
		*/

		return mapMitigationPolicies;
	}

	void CProcess::EnumeratePPLPolicies(std::function<bool(std::shared_ptr <CPPLPolicy> policy)> fn)
	{
		// TODO
	}
	auto CProcess::GetPPLPolicies()
	{
		// TODO
	}
	
	void CProcess::EnumerateTokens(std::function<bool(std::shared_ptr <CToken> token)> fn)
	{
		// TODO
	}
	auto CProcess::GetTokens()
	{
		// TODO
	}

	void CProcess::EnumerateEnvironments(std::function<bool(std::shared_ptr <CEnvironment> env)> fn)
	{
		// TODO
	}
	auto CProcess::GetEnvironments()
	{
		// TODO
	}

	void CProcess::EnumerateWindows(std::function<bool(std::shared_ptr <CWindow> window)> fn)
	{
		// TODO
	}
	auto CProcess::GetWindows()
	{
		// TODO
	}

	bool CProcess::__Open()
	{
		m_hProcessUser = NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->OpenProcess(m_dwAccessMask, m_dwProcessID);
		if (!IS_VALID_HANDLE(m_hProcessUser))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenProcess fail! Target process: %u Error: %u", m_dwProcessID, g_winAPIs->GetLastError());
			return false;
		}

		DWORD dwSessionID = 0;
		if (!g_winAPIs->ProcessIdToSessionId(m_dwProcessID, &dwSessionID))
		{
			APP_TRACE_LOG(LL_ERR, L"ProcessIdToSessionId fail! Target process: %u Error: %u", m_dwProcessID, g_winAPIs->GetLastError());
			return false;
		}
		m_dwSessionID = dwSessionID;

		APP_TRACE_LOG(LL_SYS, L"OpenProcess success! Target process: %u", m_dwProcessID);
		return true;
	}

	bool CProcess::__SetProcessBitness()
	{
		auto __IsWow64Process = [](HANDLE hProcess) {
			if (g_winAPIs->IsWow64Process2)
			{
				USHORT target_info, host_info = 0;
				if (g_winAPIs->IsWow64Process2(hProcess, &target_info, &host_info))
					return target_info != IMAGE_FILE_MACHINE_UNKNOWN; // returns IMAGE_FILE_MACHINE_UNKNOWN if not WOW64 process
			}
			else
			{
				BOOL bRet = FALSE;
				if (!g_winAPIs->IsWow64Process(hProcess, &bRet) || !bRet)
					return false;
			}

			return true;
		};

		auto bRet = false;
		
		if (m_nProcType == EProcessType::UNKNOWN && IsValid())
		{
			SYSTEM_INFO si{ 0 };
			g_winAPIs->GetNativeSystemInfo(&si);

			if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			{
				m_nProcType = EProcessType::NATIVE_32;
				bRet = true;
			}
			else if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			{
				if (__IsWow64Process(m_hProcessUser))
				{
					m_nProcType = EProcessType::WOW64;
				}
				else
				{
					m_nProcType = EProcessType::NATIVE_64;
				}
				bRet = true;
			}
		}
		
		APP_TRACE_LOG(LL_SYS, L"Process: %u type: %u", m_dwProcessID, m_nProcType);
		return bRet;
	}

	std::vector <uint8_t> CProcess::__GetTokenInformation(HANDLE hToken, TOKEN_INFORMATION_CLASS eTokenType)
	{
		DWORD nSize = 0;
		g_winAPIs->GetTokenInformation(hToken, eTokenType, nullptr, nSize, &nSize);
		
		const auto dwLastError = g_winAPIs->GetLastError();
		if (dwLastError != ERROR_INSUFFICIENT_BUFFER && dwLastError != ERROR_BAD_LENGTH)
		{
			APP_TRACE_LOG(LL_ERR, L"GetTokenInformation (1) fail! Error: %u", dwLastError);
			return {};
		}
		
		std::vector <uint8_t> pBuffer(nSize);
		if (!g_winAPIs->GetTokenInformation(hToken, eTokenType, pBuffer.data(), nSize, &nSize))
		{
			APP_TRACE_LOG(LL_ERR, L"GetTokenInformation (2) fail! Error: %u", g_winAPIs->GetLastError());
			return {};
		}
		
		return pBuffer;
	}

	std::vector <uint8_t> CProcess::__GetProcessInformation(TOKEN_INFORMATION_CLASS eTokenType)
	{
		if (!m_hProcessUser)
		{
			return {};
		}
		
		HANDLE hToken = nullptr;
		if (!g_winAPIs->OpenProcessToken(m_hProcessUser, TOKEN_QUERY, &hToken))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenProcessToken fail! Error: %u", g_winAPIs->GetLastError());
			return {};
		}			
		
		const auto bRet = this->__GetTokenInformation(hToken, eTokenType);

		g_winAPIs->CloseHandle(hToken);
		return bRet;
	}
}
