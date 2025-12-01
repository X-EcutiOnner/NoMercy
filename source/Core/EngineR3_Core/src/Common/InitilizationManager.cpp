#include "../../include/PCH.hpp"
#include "../../include/InitilizationManager.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/ProcessFunctions.hpp"
#include "../../include/Elevation.hpp"
#include "../../include/resource.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/Splash.hpp"
#include "../../../../Common/FilePtr.hpp"

namespace NoMercyCore
{
	static void __DummyFunc()
	{
	}
	HMODULE __GetCurrentModule()
	{
		HMODULE hModule = nullptr;
		GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)__DummyFunc, &hModule);
		return hModule;
	}

	CInitilizationManager::CInitilizationManager()
	{
	}
	CInitilizationManager::~CInitilizationManager()
	{
		if (m_pSplash)
		{
			m_pSplash->CloseSplash();
			m_pSplash = nullptr;
		}
	}

	bool CInitilizationManager::IsProcessProtected()
	{
#if !defined(_DEBUG) && !defined(_RELEASE_DEBUG_MODE_)
#if USE_THEMIDA_SDK == 1
		int StatusProtection = 0;
		CHECK_PROTECTION(StatusProtection, 0x33333333);

		int StatusCodeIntegrity = 0;
		CHECK_CODE_INTEGRITY(StatusCodeIntegrity, 0x44444444);

		if (StatusProtection != 0x33333333 || StatusCodeIntegrity != 0x44444444)
#elif USE_ENIGMA_SDK == 1
		if (EP_CheckupIsProtected() && EP_CheckupIsEnigmaOk() == FALSE)
#elif USE_VMPROTECT_SDK == 1
		if (VMProtectIsProtected() == FALSE || VMProtectIsValidImageCRC() == FALSE)
#elif USE_SHIELDEN_SDK == 1
		if (SECheckProtection() == FALSE)
#else
		if (false)
#endif
		{
			APP_TRACE_LOG(LL_CRI, L"Protection is changed/cracked...");
			return false;
		}
#endif

		return true;
	}

	int CInitilizationManager::CheckElevation()
	{
#ifndef _DEBUG
		// if (CElevationHelper::IsApplicationRequiredUAC(stdext::to_wide(CApplication::Instance().DirFunctionsInstance()->ExeNameWithPath())))
		{
			if (!CElevationHelper::IsUserAdmin())
				return 1;

			if (!CElevationHelper::IsRunAsAdmin())
				return 2;

			if (!CElevationHelper::IsProcessElevated(NtCurrentProcess()))
				return 3;
		}
#endif

		return 0;
	}

	bool CInitilizationManager::RequestPrivilege(ULONG ulPriv)
	{
		if (IsWindowsVistaOrGreater())
		{
			BOOLEAN bPrevStatus = FALSE;
			const auto ntStatus = g_winAPIs->RtlAdjustPrivilege(ulPriv, TRUE, FALSE, &bPrevStatus);
	
			APP_TRACE_LOG(LL_WARN, L"RtlAdjustPrivilege Status: %p Prev: %d", ntStatus, bPrevStatus);

			return NT_SUCCESS(ntStatus) || ntStatus == STATUS_ACCESS_DENIED;
		}
		return true;
	}

	bool CInitilizationManager::RestartCurrentProcessAsAdmin()
	{
		DWORD dwPathSize = MAX_PATH;
		WCHAR wszPath[MAX_PATH]{ L'\0' };
		if (!g_winAPIs->QueryFullProcessImageNameW(NtCurrentProcess(), 0, wszPath, &dwPathSize))
		{
			APP_TRACE_LOG(LL_ERR, L"QueryFullProcessImageNameW failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		int err = 0;
		return StartAsAdmin(wszPath, xorstr_(L"--delay 5000"), err);
	}
	bool CInitilizationManager::StartAsAdmin(const std::wstring& file, const std::wstring& param, int& error)
	{
		if (file.find_last_of(xorstr_(L".")) != std::wstring::npos)
		{
			const auto ext = file.substr(file.find_last_of(xorstr_(L".")) + 1);
			if (ext != xorstr_(L"exe"))
			{
				APP_TRACE_LOG(LL_CRI, L"StartAsAdmin: File extension is not exe: '%s' !!!", file.c_str());
			}
		}

		// Initialize COM before calling ShellExecute().
		g_winAPIs->CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE);

		auto wszParam = xorstr_(L"runas");
		const auto iExecuteRet = (INT_PTR)g_winAPIs->ShellExecuteW(nullptr, wszParam, file.c_str(), param.empty() ? nullptr : param.data(), nullptr, SW_SHOW);
		if (iExecuteRet > 32) // If the function succeeds, it returns a value greater than 32.
			return true;

		error = iExecuteRet;
		APP_TRACE_LOG(LL_ERR, L"ShellExecuteW (%ls) failed with status: %u error: %u", file.c_str(), iExecuteRet, g_winAPIs->GetLastError());
		return false;
	}
	bool CInitilizationManager::StartAsAdminNative(const std::wstring& file, const std::wstring& param, int& error)
	{
		auto bRet = false;
		HANDLE hToken = nullptr;
		HANDLE hNewToken = nullptr;
		PTOKEN_USER pUser = nullptr;

		do
		{
			// Get the primary access token of the current user
			if (!g_winAPIs->OpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hToken))
			{
				APP_TRACE_LOG(LL_ERR, L"OpenProcessToken failed with error: %u", g_winAPIs->GetLastError());
				error = 1;
				break;
			}

			// Duplicate the primary token to create a new token with elevated privileges
			if (!g_winAPIs->DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hNewToken))
			{
				APP_TRACE_LOG(LL_ERR, L"DuplicateTokenEx failed with error: %u", g_winAPIs->GetLastError());
				error = 2;
				break;
			}

			// Get the user information from the token
			DWORD dwSize = 0;
			g_winAPIs->GetTokenInformation(hNewToken, TokenUser, NULL, 0, &dwSize);
			if (dwSize == 0)
			{
				APP_TRACE_LOG(LL_ERR, L"GetTokenInformation failed with error: %u", g_winAPIs->GetLastError());
				error = 3;
				break;
			}

			pUser = (PTOKEN_USER)CMemHelper::Allocate(dwSize);
			if (!pUser)
			{
				APP_TRACE_LOG(LL_ERR, L"Allocate failed with error: %u", g_winAPIs->GetLastError());
				error = 4;
				break;
			}

			if (!g_winAPIs->GetTokenInformation(hNewToken, TokenUser, pUser, dwSize, &dwSize))
			{
				APP_TRACE_LOG(LL_ERR, L"GetTokenInformation failed with error: %u", g_winAPIs->GetLastError());
				error = 5;
				break;
			}

			// Merge file name and parameters into a command line string
			std::wstring wstCommandLine = file;
			APP_TRACE_LOG(LL_SYS, L"Raw Command line: %s", wstCommandLine.c_str());

			if (file.find(xorstr_(L" ")) != std::wstring::npos)
			{
				wstCommandLine = xorstr_(L"\"") + wstCommandLine + xorstr_(L"\"");
				APP_TRACE_LOG(LL_SYS, L"Quoted Command line: %s", wstCommandLine.c_str());
			}

			if (!param.empty())
			{
				wstCommandLine += xorstr_(L" ");
				wstCommandLine += param;
			}
			APP_TRACE_LOG(LL_SYS, L"Command line: %s", wstCommandLine.c_str());

			// Create the process with elevated privileges
			PROCESS_INFORMATION pi{};
			ZeroMemory(&pi, sizeof(pi));

			STARTUPINFOW si{};
			ZeroMemory(&si, sizeof(si));
			si.cb = sizeof(si);

			if (!g_winAPIs->CreateProcessAsUserW(
				hNewToken,
				NULL,
				const_cast<wchar_t*>(wstCommandLine.c_str()),
				NULL,
				NULL,
				FALSE,
				CREATE_DEFAULT_ERROR_MODE | CREATE_NEW_CONSOLE,
				NULL,
				NULL,
				&si,
				&pi
			))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateProcessAsUserW failed with error: %u", g_winAPIs->GetLastError());
				error = 6;
				break;
			}
			else
			{
				APP_TRACE_LOG(LL_SYS, L"CreateProcessAsUserW(%s) succeeded", file.c_str());
			}

			bRet = true;
		} while (FALSE);

		if (hNewToken)
		{
			g_winAPIs->CloseHandle(hNewToken);
			hNewToken = nullptr;
		}
		if (hToken)
		{
			g_winAPIs->CloseHandle(hToken);
			hToken = nullptr;
		}
		if (pUser)
		{
			CMemHelper::Free(pUser);
			pUser = nullptr;
		}

		return bRet;
	}

	void CInitilizationManager::SetNoMercyPath(const std::wstring& stPath)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

#if defined(BYPASS_NOMERCY_SYSTEM_PATH) || defined(_DEBUG)
		m_stNoMercyPath = CApplication::Instance().DirFunctionsInstance()->CurrentPath();
#elif defined(_RELEASE_DEBUG_MODE_)
		m_stNoMercyPath = fmt::format(xorstr_(L"{0}\\NoMercy"), CApplication::Instance().DirFunctionsInstance()->CurrentPath());
#else
		m_stNoMercyPath = stPath;
#endif

		APP_TRACE_LOG(LL_SYS, L"Setting NoMercy path to: '%s'", m_stNoMercyPath.c_str());
		return;
	}

	std::wstring CInitilizationManager::GetI18nW(ELocalizationPhase phase, const uint32_t id, const uint32_t sub_id)
	{
		return GetI18nW((const uint8_t)phase, id, sub_id);
	}
	std::wstring CInitilizationManager::GetI18nW(const uint8_t phase, const uint32_t id, const uint32_t sub_id)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		for (const auto& i18n : m_vLanguageData)
		{
			if (IS_VALID_SMART_PTR(i18n))
			{
				if (i18n->phase == phase)
				{
					if ((i18n->index == id && !i18n->sub_code) ||
						(i18n->index == id && i18n->sub_code && i18n->sub_code == sub_id))
					{
						return i18n->context;
					}
				}
			}
		}
		return L"";
	}

	bool CInitilizationManager::__ProcessLocalizationData(const std::wstring& stBuffer, uint8_t& fail_step)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		auto document = rapidjson::GenericDocument<UTF16<>>{};
		try
		{
			document.Parse<kParseCommentsFlag>(stBuffer.data());
			if (document.HasParseError())
			{
				APP_TRACE_LOG(LL_ERR, L"Language file could NOT parsed! Error: %hs offset: %u", GetParseError_En(document.GetParseError()), document.GetErrorOffset());
				fail_step = 10;
				return false;
			}

			if (!document.IsObject())
			{
				APP_TRACE_LOG(LL_ERR, L"Language file base is not an object! Type: %u", document.GetType());
				fail_step = 11;
				return false;
			}

			uint32_t phase_idx = 0;
			uint32_t idx = 0;
			for (auto phase_node = document.MemberBegin(); phase_node != document.MemberEnd(); ++phase_node)
			{
				phase_idx++;

				if (!phase_node->name.IsString())
				{
					APP_TRACE_LOG(LL_ERR, L"Language phase node: %u key is not a string. Type: %u", phase_idx, phase_node->name.GetType());
					fail_step = 12;
					return false;
				}
				if (!phase_node->value.IsObject())
				{
					APP_TRACE_LOG(LL_ERR, L"Language phase node: %u value is not a object. Type: %u", phase_idx, phase_node->value.GetType());
					fail_step = 13;
					return false;
				}

				const std::wstring current_phase_str = phase_node->name.GetString();
				if (!stdext::is_number(current_phase_str))
				{
					APP_TRACE_LOG(LL_ERR, L"Language phase context is not a number. Data: %s", current_phase_str.c_str());
					fail_step = 14;
					return false;
				}
				const auto current_phase_num = stdext::str_to_u32(current_phase_str);

				for (auto node = phase_node->value.MemberBegin(); node != phase_node->value.MemberEnd(); ++node)
				{
					idx++;

					if (!node->name.IsString())
					{
						APP_TRACE_LOG(LL_ERR, L"Language file node: %u key is not a string. Phase: %s Type: %u", idx, current_phase_str.c_str(), node->name.GetType());
						fail_step = 15;
						return false;
					}
					if (!node->value.IsString())
					{
						APP_TRACE_LOG(LL_ERR, L"Language file node: %u value is not a string. Phase: %s Type: %u", idx, current_phase_str.c_str(), node->value.GetType());
						fail_step = 16;
						return false;
					}

					const auto wstKey = std::wstring(node->name.GetString(), node->name.GetStringLength());
					const auto bHasDotInKey = wstKey.find(xorstr_(L".")) != std::wstring::npos;
					if (!stdext::is_number(wstKey) && !bHasDotInKey)
					{
						APP_TRACE_LOG(LL_ERR, L"Language file node: %u key context not a number. Phase: %s Data: %s", idx, current_phase_str.c_str(), wstKey.c_str());
						fail_step = 17;
						return false;
					}

					uint32_t err_idx = 0, sub_idx = 0;
					if (bHasDotInKey)
					{
						const auto vecSplittedData = stdext::split_string(wstKey, std::wstring(xorstr_(L".")));
						if (vecSplittedData.size() != 2)
						{
							APP_TRACE_LOG(LL_ERR, L"Corrupted data: '%s' is contain %u dot char", wstKey.c_str(), vecSplittedData.size());
							fail_step = 18;
							return false;
						}
						const auto wstFirstPart	= vecSplittedData.at(0);
						const auto wstSecondPart = vecSplittedData.at(1);

						if (!stdext::is_number(wstFirstPart) || !stdext::is_number(wstSecondPart))
						{
							APP_TRACE_LOG(LL_ERR, L"Corrupted data: '%s' is contain non-number chars", wstKey.c_str());
							fail_step = 19;
							return false;
						}

						err_idx = stdext::str_to_u32(wstFirstPart);
						sub_idx = stdext::str_to_u32(wstSecondPart);
					}
					else
					{
						err_idx = stdext::str_to_u32(wstKey);
					}

					auto data = stdext::make_shared_nothrow<SI18nContext>();
					if (!data)
					{
						APP_TRACE_LOG(LL_ERR, L"Language context container allocation failed!");
						fail_step = 20;
						return false;
					}

					data->phase = static_cast<uint8_t>(current_phase_num);
					data->index = err_idx;
					data->sub_code = sub_idx;
					data->context = node->value.GetString();

					m_vLanguageData.emplace_back(data);
					APP_TRACE_LOG(LL_TRACE, L"[%u] I18N parsing... [%u] %u -> %s", idx, data->phase, data->index, node->value.GetString());
				}
			}
		}
		catch (const std::exception& e)
		{
			APP_TRACE_LOG(LL_ERR, L"Exception handled on parse locale config file, Error: %hs", e.what());
			fail_step = 1;
			return false;
		}

		return true;
	}

	bool CInitilizationManager::LoadLocalizationFile(const uint8_t app_type, HINSTANCE hInstance, uint8_t& fail_step)
	{
		const auto mapI18nResources = std::map <std::wstring, uint32_t>{
			{ xorstr_(L"en"), NM_I18N_EN },
			{ xorstr_(L"tr"), NM_I18N_TR },
		};

		auto fnLoadFromResources = [&](const std::wstring& wstLocale) {
			APP_TRACE_LOG(LL_SYS, L"Loading I18N from resources... Locale: %s", wstLocale.c_str());

			if (!hInstance)
			{
				APP_TRACE_LOG(LL_ERR, L"hInstance is nullptr");
				fail_step = 3;
				return false;
			}

			uint32_t nTargetLocaleID = 0;

			const auto it = mapI18nResources.find(wstLocale);
			if (it == mapI18nResources.end())
			{
				APP_TRACE_LOG(LL_ERR, L"Target locale: %s is undefined!", wstLocale.c_str());
				nTargetLocaleID = NM_I18N_EN;
			}
			else
			{
				nTargetLocaleID = it->second;
			}

			const auto c_szTargetLocale = MAKEINTRESOURCEW(nTargetLocaleID);
			APP_TRACE_LOG(LL_SYS, L"Target locale resource: %p(%u)", c_szTargetLocale, nTargetLocaleID);

			auto hResource = g_winAPIs->FindResourceW(hInstance, c_szTargetLocale, xorstr_(L"TEXTFILE"));
			if (!hResource)
			{
				APP_TRACE_LOG(LL_ERR, L"#1 FindResourceW failed with error: %u", g_winAPIs->GetLastError());

				const auto pAnticheatModule = (LDR_DATA_TABLE_ENTRY*)(CApplication::Instance().GetModuleInfo());
				if (pAnticheatModule)
					hInstance = (HINSTANCE)pAnticheatModule->DllBase;
				else
					hInstance = __GetCurrentModule();
				
				hResource = g_winAPIs->FindResourceW(hInstance, c_szTargetLocale, xorstr_(L"TEXTFILE"));
				if (!hResource)
				{
					APP_TRACE_LOG(LL_ERR, L"#2 FindResourceW failed with error: %u", g_winAPIs->GetLastError());

					/*
					// Dump all resources
					EnumResourceTypes(hInstance, [](HMODULE hModule, LPWSTR lpszType, LONG_PTR lParam) -> BOOL {
						APP_TRACE_LOG(LL_SYS, L"Resource Type: %ls", lpszType);

						EnumResourceNames(hModule, lpszType, [](HMODULE hModule, LPCWSTR lpszType, LPWSTR lpszName, LONG_PTR lParam) -> BOOL {
							APP_TRACE_LOG(LL_SYS, L"Resource Name: %ls", lpszName);
							return TRUE;
						}, NULL);

						return TRUE;
					}, NULL);
					*/

					fail_step = 4;
					return false;
				}
			}

			const auto hI18NResource = g_winAPIs->LoadResource(hInstance, hResource);
			if (!hI18NResource)
			{
				APP_TRACE_LOG(LL_ERR, L"LoadResource failed with error: %u", g_winAPIs->GetLastError());
				fail_step = 5;
				return false;
			}

			const auto dwResourceSize = g_winAPIs->SizeofResource(hInstance, hResource);
			if (!dwResourceSize)
			{
				APP_TRACE_LOG(LL_ERR, L"SizeofResource failed with error: %u", g_winAPIs->GetLastError());
				fail_step = 6;
				return false;
			}

			const auto lpI18NSource = g_winAPIs->LockResource(hI18NResource);
			if (!lpI18NSource)
			{
				APP_TRACE_LOG(LL_ERR, L"LockResource failed with error: %u", g_winAPIs->GetLastError());
				fail_step = 7;
				return false;
			}

			const auto stI18NSource = std::string(reinterpret_cast<const char*>(lpI18NSource), dwResourceSize);
			if (stI18NSource.empty() || stI18NSource.at(0) != '{')
			{
				APP_TRACE_LOG(LL_ERR, L"Corrupted resource data:\n%hs", stI18NSource.c_str());
				fail_step = 8;
				return false;
			}

			const auto wstI18NSource = stdext::utf8_to_wchar(stI18NSource);
			if (wstI18NSource.empty() || wstI18NSource.at(0) != '{')
			{
				APP_TRACE_LOG(LL_ERR, L"Corrupted resource data:\n%s", wstI18NSource.c_str());
				fail_step = 9;
				return false;
			}

			return this->__ProcessLocalizationData(wstI18NSource, fail_step);
		};

		APP_TRACE_LOG(LL_SYS, L"Localization file loading for application: %u Instance(%p)", app_type, hInstance);

		wchar_t wszLocaleBuffer[LOCALE_NAME_MAX_LENGTH]{ L'\0' };
		if (!g_winAPIs->GetSystemDefaultLocaleName(wszLocaleBuffer, LOCALE_NAME_MAX_LENGTH) || wszLocaleBuffer[0] == L'\0' || wcslen(wszLocaleBuffer) < 3)
		{
			APP_TRACE_LOG(LL_ERR, L"GetSystemDefaultLocaleName(%ls) failed with error: %u", wszLocaleBuffer, g_winAPIs->GetLastError());
			fail_step = 1;
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Target locale: %ls", wszLocaleBuffer);

		wchar_t wszParentLocaleBuffer[LOCALE_NAME_MAX_LENGTH]{ L'\0' };
		if (!g_winAPIs->GetLocaleInfoEx(wszLocaleBuffer, LOCALE_SPARENT, wszParentLocaleBuffer, LOCALE_NAME_MAX_LENGTH) ||
			wszParentLocaleBuffer[0] == L'\0' ||
			wcslen(wszParentLocaleBuffer) < 2)
		{
			APP_TRACE_LOG(LL_ERR, L"GetLocaleInfoEx(%ls) failed with error: %u", wszParentLocaleBuffer, g_winAPIs->GetLastError());
			fail_step = 2;
			return false;
		}
		APP_TRACE_LOG(LL_SYS, L"Target locale parent: %ls", wszParentLocaleBuffer);
		const auto wstLocale = stdext::to_lower_wide(wszParentLocaleBuffer);

		if (!hInstance)
		{
			hInstance = NoMercyCore::CApplication::Instance().DataInstance()->GetProcessInstance();
			APP_TRACE_LOG(LL_WARN, L"Process instance param is nullptr, using saved process instance: %p", hInstance);

			if (!hInstance)
			{
				if (app_type == NM_CLIENT)
				{
					const auto spAnticheatModule = CApplication::Instance().DataInstance()->GetAntiModuleInformations();
					if (IS_VALID_SMART_PTR(spAnticheatModule))
					{
						hInstance = (HINSTANCE)spAnticheatModule->DllBase;
						APP_TRACE_LOG(LL_WARN, L"Saved process instance is nullptr, using anti-cheat module base: %p", hInstance);
					}
					else
					{
						hInstance = __GetCurrentModule();
						APP_TRACE_LOG(LL_WARN, L"Saved process instance is nullptr, using anti-cheat module base from static func addr: %p", hInstance);
					}
				}

				if (!hInstance)
				{
					hInstance = g_winModules->hBaseModule;
					APP_TRACE_LOG(LL_WARN, L"Saved process instance is nullptr, using base module: %p", hInstance);
				}
			}

			if (!hInstance)
			{
				APP_TRACE_LOG(LL_ERR, L"Process instance is nullptr");
				fail_step = 3;
				return false;
			}
		}

		const auto stPath = CApplication::Instance().DirFunctionsInstance()->CurrentPath();
		const auto stNoMercyPath = fmt::format(xorstr_(L"{0}\\NoMercy"), stPath);
		APP_TRACE_LOG(LL_SYS, L"Current path: %s NoMercy path: %s", stPath.c_str(), stNoMercyPath.c_str());

		const auto c_szLangConfigPath = fmt::format(xorstr_(L"{0}\\I18n"), stNoMercyPath);
		if (!std::filesystem::exists(c_szLangConfigPath))
		{
			APP_TRACE_LOG(LL_WARN, L"Language path: %s does not exist", c_szLangConfigPath.c_str());
			return fnLoadFromResources(wstLocale);
		}
		if (!stdext::number_of_files_in_directory(c_szLangConfigPath))
		{
			APP_TRACE_LOG(LL_WARN, L"Language path does not contain any file");
			return fnLoadFromResources(wstLocale);
		}

		auto locale_file_path = fmt::format(xorstr_(L"{0}\\{1}.json"), c_szLangConfigPath, wstLocale);
		if (!std::filesystem::exists(locale_file_path))
		{
			APP_TRACE_LOG(LL_ERR, L"Target locale config(%s) does not exist", locale_file_path.c_str());

			locale_file_path = fmt::format(xorstr_(L"{0}\\{1}"), c_szLangConfigPath, DEFAULT_I18N_FILENAME);
			if (!std::filesystem::exists(locale_file_path))
			{
				APP_TRACE_LOG(LL_WARN, L"Default locale config: %s does not exist", locale_file_path.c_str());
				return fnLoadFromResources(wstLocale);
			}
		}

		APP_TRACE_LOG(LL_SYS, L"Target locale: %s", locale_file_path.c_str());

		auto file = msl::file_ptr(locale_file_path, xorstr_(L"rb"));
		if (!file)
		{
			APP_TRACE_LOG(LL_ERR, L"Language file could NOT mapped to memory! Error: %u", g_winAPIs->GetLastError());
			fail_step = 6;
			return false;
		}

		const auto stBuffer = file.string_read();
		if (stBuffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Language file could NOT read! Error: %u", g_winAPIs->GetLastError());
			fail_step = 7;
			return false;
		}

		const auto wstBuffer = stdext::utf8_to_wchar(stBuffer);
		if (wstBuffer.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Language file could NOT convert to wide string! Error: %u", g_winAPIs->GetLastError());
			fail_step = 8;
			return false;
		}

		return this->__ProcessLocalizationData(wstBuffer, fail_step);
	}

	bool CInitilizationManager::LoadSplashImage(const HINSTANCE hInstance)
	{
		auto workerThread = [](LPVOID lpParam) -> DWORD {
			APP_TRACE_LOG(LL_SYS, L"Loading splash image from resources...");

			auto hInstance = reinterpret_cast<HINSTANCE>(lpParam);
			if (!hInstance)
			{
				APP_TRACE_LOG(LL_ERR, L"hInstance is nullptr");

				const auto pAnticheatModule = (LDR_DATA_TABLE_ENTRY*)(CApplication::Instance().GetModuleInfo());
				if (pAnticheatModule)
					hInstance = (HINSTANCE)pAnticheatModule->DllBase;

				if (!hInstance)
					hInstance = __GetCurrentModule();
			}

			const auto c_wszResID = MAKEINTRESOURCEW(NM_SPLASH_IMAGE);
			APP_TRACE_LOG(LL_SYS, L"Resource ID: %p(%u)", c_wszResID, NM_SPLASH_IMAGE);
			
			auto hBitmap = g_winAPIs->LoadBitmapW(hInstance, c_wszResID);
			if (!hBitmap)
			{
				APP_TRACE_LOG(LL_ERR, L"LoadBitmapW failed with error: %u", g_winAPIs->GetLastError());
				return 0;
			}

			auto pSplash = new CSplash(hBitmap, RGB(128, 128, 128));
			if (!pSplash)
			{
				APP_TRACE_LOG(LL_ERR, L"CSplash allocation failed!");
				return 0;
			}
			CApplication::Instance().InitilizationManagerInstance()->SetSplashImagePtr(pSplash);

			pSplash->ShowSplash();
			return 0;
		};

		auto hThread = g_winAPIs->CreateThread(nullptr, 0, workerThread, nullptr, 0, nullptr);
		if (!hThread)
		{
			APP_TRACE_LOG(LL_ERR, L"CreateThread failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		g_winAPIs->CloseHandle(hThread);
		return true;
	}
	void CInitilizationManager::CloseSplashImage()
	{
		if (m_pSplash)
		{
			m_pSplash->CloseSplash();

			delete m_pSplash;
			m_pSplash = nullptr;
		}
	}
};
