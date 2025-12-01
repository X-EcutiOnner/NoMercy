#include "../../include/PCH.hpp"
#include "../../include/Data.hpp"
#include "../../../../Common/StdExtended.hpp"

namespace NoMercyCore
{
	CData::CData(uint8_t eAppType)
	{
		__Initialize();

		m_iAppType = eAppType;
	}
	CData::~CData()
	{
		__Initialize();

		m_pAntiModuleInfo.reset();
		m_pAntiModuleInfo = nullptr;
	}

	void CData::__Initialize()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_bConnectedToBackend = false;
		m_bConnectionDisconnected = false;

		m_bWatchdogFirstChecked = false;
		m_bAdminEnv = false;

		m_dwTelemetryProcessId = 0;
		m_dwErrorCode = 0;

		m_pAntiModuleInfo = stdext::make_shared_nothrow<LDR_DATA_TABLE_ENTRY>();

		m_strLauncherName = L"";
		m_hPythonHandle = nullptr;
		m_strPythonName = L"";
		m_bIsProcessPacked = false;
		m_bIsShadowProcess = false;
		m_hShadowProcess = INVALID_HANDLE_VALUE;
		m_dwNoMercyVersion = 0;

		m_mScreenProtectionStatus.clear();

		m_hInstance = nullptr;
		m_iAppType = 0;
		m_iGameCode = 0;
		m_dwMainThreadId = 0;
		m_hMainThread = nullptr;
		m_dwInitOptions = 0;
		m_dwClientLimit = 0;
		m_bIsDisabled = false;
		m_bUseCrashHandler = true;
		m_bCompabilityMode = false;
		m_bBlockLauncherUpdate = false;
		m_hClientWnd = nullptr;

		m_dwStage = 0;
		m_strStage = L"";
		m_strStageKey = L"";
		m_dwVersion = 0;
		m_bHeartbeatEnabled = false;
		m_dwHeartbeatType = 0;
		m_dwHeartbeatIntervalMs = 5000;
		m_dwHeartbeatSeed = 0;
		m_bNetGuardEnabled = false;
		m_dwNetGuardVersion = 0;
		m_qwNetGuardSeed = 0;
		m_bLauncherIntegrityCheckEnabled = false;
		m_strLauncherExecutable = L"";
		m_strLauncherExecutableHash = L"";

		m_strUserToken = L"";

		m_dwSecurityLevel = 0;
		m_dwDisabledFuncs = 0;
		m_dwEmulatorIndex = 0;
	}

	// NoMercy module helpers
	void CData::SetAntiModuleInformations(LPCVOID lpModuleInfo)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		if (lpModuleInfo)
			memcpy(m_pAntiModuleInfo.get(), lpModuleInfo, sizeof(LDR_DATA_TABLE_ENTRY));
	}
	std::wstring CData::GetAntiFileName() const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		if (IS_VALID_SMART_PTR(m_pAntiModuleInfo) && m_pAntiModuleInfo->BaseDllName.Length && m_pAntiModuleInfo->BaseDllName.Buffer)
		{
			const auto wstFileName = stdext::to_lower_wide(m_pAntiModuleInfo->BaseDllName.Buffer);
			return wstFileName;
		}
		return L"";
	}
	std::wstring CData::GetAntiFullName() const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		if (IS_VALID_SMART_PTR(m_pAntiModuleInfo) && m_pAntiModuleInfo->FullDllName.Length && m_pAntiModuleInfo->FullDllName.Buffer)
		{
			const auto wstFullName = stdext::to_lower_wide(m_pAntiModuleInfo->FullDllName.Buffer);
			return wstFullName;
		}
		return L"";
	}

	// License helpers
	bool CData::HasLicensedIp() const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		return !m_vLicensedIPs.empty();
	}
	bool CData::IsLicensedIp(const std::wstring& stIP) const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
		
		return std::find(m_vLicensedIPs.begin(), m_vLicensedIPs.end(), stIP) != m_vLicensedIPs.end();
	}
	void CData::AddLicensedIp(const std::wstring& stIP)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		if (!stIP.empty())
			m_vLicensedIPs.emplace_back(stIP);

		return;
	}
	std::wstring CData::GetLicensedIPsString()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		std::wstring out;
		if (m_vLicensedIPs.empty())
			return out;

		for (const auto& ip : m_vLicensedIPs)
		{
			out += xorstr_(L"'");
			out += ip;
			out += xorstr_(L"',");
		}
		out.pop_back();

		return out;
	}

	// Screen protection
	bool CData::IsProtectedWindow(HWND hWnd) const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		return m_mScreenProtectionStatus.find(hWnd) != m_mScreenProtectionStatus.end();
	}
	bool CData::GetScreenProtectionStatus(HWND hWnd) const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		const auto stat = m_mScreenProtectionStatus.find(hWnd);
		return stat->second;
	}
	void CData::UpdateScreenProtectionStatus(HWND hWnd, bool bNew)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_mScreenProtectionStatus[hWnd] = bNew;
	}
}
