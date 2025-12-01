#include "../../include/PCH.hpp"
#include "../../include/Functions.hpp"
#include <fcntl.h>

namespace NoMercyCore
{
	CFunctions::CFunctions()
	{
	}
	CFunctions::~CFunctions()
	{
	}

	std::string CFunctions::GetCurrentTimeString()
	{
		const auto fnGetTime = LI_FN(GetLocalTime).forwarded_safe();
		if (!fnGetTime)
			return "";

		SYSTEMTIME sysTime{ 0 };
		fnGetTime(&sysTime);

		char szTimeBuf[1024]{ '\0' };
		snprintf(szTimeBuf, sizeof(szTimeBuf),
			xorstr_("%02d-%02d-%02d_%02d-%02d-%d"),
			sysTime.wHour, sysTime.wMinute, sysTime.wSecond, sysTime.wDay, sysTime.wMonth, sysTime.wYear
		);
		return szTimeBuf;
	}

	std::string CFunctions::GetFixedBuildDate()
	{
		char szFixDate[512]{ '\0' };
		snprintf(szFixDate, sizeof(szFixDate), xorstr_("%s-%s"), xorstr_(__DATE__), xorstr_(__TIME__));

		std::string stFixDate(szFixDate);
		stdext::replace_all<std::string>(stFixDate, xorstr_(":"), "");
		stdext::replace_all<std::string>(stFixDate, xorstr_(" "), "");
		return stFixDate;
	};

	std::wstring CFunctions::FindExecutableRealPath(const std::wstring& wstPath)
	{
		std::error_code ec{};
		if (wstPath.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Executable path is empty!");
			return {};
		}
		else if (wstPath.find(xorstr_(L".")) == std::wstring::npos)
		{
			APP_TRACE_LOG(LL_ERR, L"Executable path is not relative path!");
			return {};
		}
		APP_TRACE_LOG(LL_SYS, L"Executable: %ls", wstPath.c_str());

		auto nSlashPos = wstPath.find_last_of(xorstr_(L"\\"));
		if (nSlashPos == std::wstring::npos)
		{
			APP_TRACE_LOG(LL_ERR, L"Executable: %ls found path does not have a slash in executable!", wstPath.c_str());
			return {};
		}

		auto wstExecutableName = wstPath.substr(nSlashPos + 1);
		if (wstExecutableName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Executable: %ls found path does not have a name in executable!", wstPath.c_str());
			return {};
		}
		APP_TRACE_LOG(LL_SYS, L"Executable name: %ls", wstExecutableName.c_str());

		const auto kFsPath = std::filesystem::path(wstPath);
		if (!kFsPath.has_parent_path())
		{
			APP_TRACE_LOG(LL_ERR, L"Executable: %ls found path does not have path!", wstPath.c_str());
			return {};
		}

		const auto wstCurrentPath = kFsPath.parent_path().wstring();
		if (!std::filesystem::exists(wstCurrentPath, ec))
		{
			APP_TRACE_LOG(LL_ERR, L"Current path: %ls does not exist!", wstCurrentPath.c_str());
//			return {};
		}
		APP_TRACE_LOG(LL_SYS, L"Path: %ls", wstCurrentPath.c_str());

		nSlashPos = wstCurrentPath.find_last_of(xorstr_(L"\\"));
		if (nSlashPos == std::wstring::npos)
		{
			APP_TRACE_LOG(LL_ERR, L"Executable: %ls found path does not have a slash in parent path!", wstPath.c_str());
			return {};
		}

		const auto wstCurrentPathName = wstCurrentPath.substr(nSlashPos + 1);
		if (wstCurrentPathName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Executable: %ls found path can not split parent path!", wstPath.c_str());
			return {};
		}
		APP_TRACE_LOG(LL_SYS, L"Current path name: '%ls' with size: %zu", wstCurrentPathName.c_str(), wstCurrentPathName.size());

		const auto wstParentPath = std::filesystem::path(wstCurrentPath).parent_path().wstring();
		if (!std::filesystem::exists(wstParentPath, ec))
		{
			APP_TRACE_LOG(LL_ERR, L"Parent path: %ls does not exist!", wstParentPath.c_str());
			return {};
		}
		APP_TRACE_LOG(LL_SYS, L"Parent path: %ls", wstParentPath.c_str());

		std::map <std::wstring, uint16_t> mapSimilarityList;

		auto idx = 0u;
		for (const auto& entry : std::filesystem::directory_iterator(wstParentPath, ec))
		{
			if (entry.is_directory(ec))
			{
				idx++;

				const auto wstEntryName = entry.path().wstring();
				if (wstEntryName.empty())
				{
					continue;
				}

				APP_TRACE_LOG(LL_SYS, L"[%u] Directory: %ls", idx, wstEntryName.c_str());

				nSlashPos = wstEntryName.find_last_of(xorstr_(L"\\"));
				if (nSlashPos == std::wstring::npos)
				{
					continue;
				}

				const auto wstEntryNameSplit = wstEntryName.substr(nSlashPos + 1);
				if (wstEntryNameSplit.empty())
				{
					continue;
				}

				APP_TRACE_LOG(LL_SYS, L"Target path name: %ls with %zu", wstEntryNameSplit.c_str(), wstEntryNameSplit.size());

				// Calculate similarity
				if (wstEntryNameSplit.size() == wstCurrentPathName.size())
				{
					if (wstEntryName.size() >= 7 && wstEntryName.substr(0, 7) == xorstr_(L"Default"))
					{
						APP_TRACE_LOG(LL_SYS, L"Target path name: %ls starts with 'Default', skipped!", wstEntryNameSplit.c_str());
						continue;
					}

					auto nSimilarity = 0;
					for (size_t i = 0; i < wstEntryNameSplit.size(); ++i)
					{
						if (wstEntryNameSplit[i] == wstCurrentPathName[i])
							++nSimilarity;
					}
					mapSimilarityList[wstEntryNameSplit] = nSimilarity;

					APP_TRACE_LOG(LL_SYS, L"Similarity: %ls with score: %u/%u", wstEntryNameSplit.c_str(), nSimilarity, wstEntryNameSplit.size());
				}
				else
				{
					APP_TRACE_LOG(LL_WARN, L"Similarity check skipped for %ls, size mismatch: %u/%u", wstEntryNameSplit.c_str(), wstEntryNameSplit.size(), wstCurrentPathName.size());
				}
			}
		}

		if (mapSimilarityList.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Does not found any similar directory!");
			return {};
		}

		// Check multiple similar directories
		if (mapSimilarityList.size() > 1)
		{
			APP_TRACE_LOG(LL_WARN, L"Found multiple similar directories!");

			// Sort mapSimilarityList by value high to low
			std::vector <std::pair <std::wstring, uint16_t>> vecSortedSimilarityList(mapSimilarityList.begin(), mapSimilarityList.end());
			std::sort(vecSortedSimilarityList.begin(), vecSortedSimilarityList.end(),
				[](const std::pair <std::wstring, uint16_t>& a, const std::pair <std::wstring, uint16_t>& b) {
					return a.second > b.second;
				}
			);

			// Iterate
			for (const auto& [wstEntryNameSplit, nSimilarity] : vecSortedSimilarityList)
			{
				if (nSimilarity > 0)
				{
					const auto wstOutput = fmt::format(xorstr_(L"{0}\\{1}\\{2}"), wstParentPath, wstEntryNameSplit, wstExecutableName);
					APP_TRACE_LOG(LL_SYS, L"Entry: %ls Similarity: %u Check path: %ls", wstEntryNameSplit.c_str(), nSimilarity, wstOutput.c_str());

					if (std::filesystem::exists(wstOutput, ec))
					{
						APP_TRACE_LOG(LL_SYS, L"Found similar directory: %ls", wstOutput.c_str());
						return wstOutput;
					}
					else
					{
						APP_TRACE_LOG(LL_WARN, L"Similar directory: %ls does not exist!", wstOutput.c_str());
					}
				}
			}

			APP_TRACE_LOG(LL_ERR, L"Does not found any similar directory from multiple checks!");
			return {};
		}
		else
		{
			const auto wstSimilarityName = mapSimilarityList.begin()->first;
			if (wstSimilarityName.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Similarity name is empty!");
				return {};
			}
			APP_TRACE_LOG(LL_SYS, L"Parent path: %ls, Similarity name: %ls", wstParentPath.c_str(), wstSimilarityName.c_str());

			const auto wstOutput = fmt::format(xorstr_(L"{0}\\{1}\\{2}"), wstParentPath, wstSimilarityName, wstExecutableName);
			APP_TRACE_LOG(LL_SYS, L"Output path: %ls", wstOutput.c_str());

			return wstOutput;
		}
	};

#if defined(_DEBUG) || defined(_RELEASE_DEBUG_MODE_)
	bool EnableVirtualTerminal(HANDLE* phVirtCons, DWORD* pdwOldMode)
	{
		bool bRet = false;
		HANDLE hMyCon = INVALID_HANDLE_VALUE;
		DWORD dwMyDefaultMode = 0;
		DWORD dwMode = 0;

		do
		{
			// Change console output to display Unicode characters
			if (_setmode(_fileno(stdout), _O_U16TEXT) == -1)
			{
				APP_TRACE_LOG(LL_ERR, L"_setmode (_O_U16TEXT) failed with error: %u", errno);
				break;
			}

			// Backup default console output mode
			hMyCon = GetStdHandle(STD_OUTPUT_HANDLE);
			if (hMyCon == INVALID_HANDLE_VALUE)
			{
				APP_TRACE_LOG(LL_ERR, L"GetStdHandle failed with error: %u", GetLastError());
				break;
			}

			if (!GetConsoleMode(hMyCon, &dwMyDefaultMode))
			{
				APP_TRACE_LOG(LL_ERR, L"GetConsoleMode failed with error: %u", GetLastError());
				break;
			}

			// Enable virtual terminal
			dwMode = dwMyDefaultMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;

			if (!SetConsoleMode(hMyCon, dwMode))
			{
				APP_TRACE_LOG(LL_ERR, L"SetConsoleMode failed with error: %u", GetLastError());
				break;
			}

			*pdwOldMode = dwMyDefaultMode;
			*phVirtCons = hMyCon;
			bRet = true;
		} while (FALSE);

		return bRet;
	}

	int CFunctions::OpenConsoleWindowEx()
	{
		auto GetParentProcessID = [](DWORD dwTargetPID) -> DWORD {
			auto dwPID = 0;

			if (!dwTargetPID)
				return dwPID;

			auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (!IS_VALID_HANDLE(hSnapshot))
				return dwPID;

			PROCESSENTRY32W entry = { sizeof(entry) };
			if (Process32First(hSnapshot, &entry))
			{
				do
				{
					if (dwTargetPID == entry.th32ProcessID)
					{
						dwPID = entry.th32ParentProcessID;
						break;
					}
				} while (Process32Next(hSnapshot, &entry));
			}

			CloseHandle(hSnapshot);
			return dwPID;
		};

		const auto nAppType = NoMercyCore::CApplication::Instance().GetAppType();
		if (!IsDebuggerPresent())
			return 0;

		if (GetConsoleWindow() && IsWindow(GetConsoleWindow()))
		{
			DWORD dwProcessId = 0;
			GetWindowThreadProcessId(GetConsoleWindow(), &dwProcessId);

			APP_TRACE_LOG(LL_SYS, L"Already has a console, owner: %u", dwProcessId);
			return 0;
		}

		auto dwHostPID = GetCurrentProcessId();
		if (!AttachConsole(dwHostPID))
			return -1;

		if (!IsDebuggerPresent() && !AllocConsole())
			return -2;

		FILE* pFile = nullptr;
		freopen_s(&pFile, "CONIN$", "r", stdin);
		freopen_s(&pFile, "CONOUT$", "w", stdout);
		freopen_s(&pFile, "CONOUT$", "w", stderr);

		auto hStdIn = GetStdHandle(STD_OUTPUT_HANDLE);
		if (!IS_VALID_HANDLE(hStdIn))
			return -3;

		CONSOLE_SCREEN_BUFFER_INFO csbiInfo{ 0 };
		if (!GetConsoleScreenBufferInfo(hStdIn, &csbiInfo))
			return -4;

		if (!SetConsoleTextAttribute(hStdIn, FOREGROUND_GREEN | FOREGROUND_INTENSITY))
			return -5;

		Sleep(500);

		const auto stAppType = GetAppTypeNameA(nAppType);
		char szTitle[512]{ '\0' };
		sprintf(szTitle, "NoMercy debug console | APP: %u(%s) PID: %u",
			nAppType, stAppType.c_str(), GetCurrentProcessId()
		);

		if (!SetConsoleTitleA(szTitle))
			return -6;

		HANDLE hVirtualConsole = nullptr;
		DWORD dwConsoleOldMode = 0;
		if (!EnableVirtualTerminal(&hVirtualConsole, &dwConsoleOldMode))
			return -7;

		return 0;
	}

	void CFunctions::OpenConsoleWindow()
	{
		const auto nRet = OpenConsoleWindowEx();
		if (nRet < 0 && !IsDebuggerPresent())
		{
			APP_TRACE_LOG(LL_CRI, L"Console could not open! Error code: %d", nRet);
		}
		else
		{
			APP_TRACE_LOG(LL_SYS, L"Console succesfully attached!");
		}
	}
#endif
};
