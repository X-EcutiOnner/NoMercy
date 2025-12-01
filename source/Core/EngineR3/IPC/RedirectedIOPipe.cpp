#include "../PCH.hpp"
#include "RedirectedIOPipe.hpp"

namespace NoMercy
{
	CRedirectedIOPipe::CRedirectedIOPipe(std::shared_ptr <SRedirectedIOPipeCtx> spPipeCtx) :
		m_bUnicode(false), m_bFirstExec(true), m_spClientCtx(std::move(spPipeCtx)), m_hConsoleProc(nullptr),
		m_hInReadPipe(nullptr), m_hInWritePipe(nullptr), m_hOutReadPipe(nullptr), m_hOutWritePipe(nullptr)
	{
	}
	CRedirectedIOPipe::~CRedirectedIOPipe()
	{
		this->Release();
	}

	void CRedirectedIOPipe::Release()
	{
		m_stLastCommand = "";
		m_bFirstExec = true;

		if (m_hConsoleProc)
		{
			g_winAPIs->TerminateProcess(m_hConsoleProc, EXIT_SUCCESS);
			m_hConsoleProc = nullptr;
		}

		if (m_hInReadPipe)
		{
			g_winAPIs->CloseHandle(m_hInReadPipe);
			m_hInReadPipe = nullptr;
		}

		if (m_hInWritePipe)
		{
			g_winAPIs->CloseHandle(m_hInWritePipe);
			m_hInWritePipe = nullptr;
		}

		if (m_hOutReadPipe)
		{
			g_winAPIs->CloseHandle(m_hOutReadPipe);
			m_hOutReadPipe = nullptr;
		}

		if (m_hOutWritePipe)
		{
			g_winAPIs->CloseHandle(m_hOutWritePipe);
			m_hOutWritePipe = nullptr;
		}
	}

	bool CRedirectedIOPipe::Initialize(bool bUnicode)
	{
		m_bUnicode = bUnicode;

		// Validate client context
		if (!m_spClientCtx)
		{
			APP_TRACE_LOG(LL_ERR, L"Client context is not valid!");
			return false;
		}

		// Close old process datas
		this->Release();

		// Create security attributes
		SECURITY_ATTRIBUTES sa = { 0 };
		sa.nLength = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;
		sa.lpSecurityDescriptor = m_spClientCtx->lpSecurityDescriptor;

		// Create I/O pipes & Set inherit flag
		if (!g_winAPIs->CreatePipe(&m_hOutReadPipe, &m_hOutWritePipe, &sa, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"CreatePipe (1) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->SetHandleInformation(m_hOutReadPipe, HANDLE_FLAG_INHERIT, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"SetHandleInformation (1) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->CreatePipe(&m_hInReadPipe, &m_hInWritePipe, &sa, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"CreatePipe (2) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->SetHandleInformation(m_hInWritePipe, HANDLE_FLAG_INHERIT, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"SetHandleInformation (2) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Disable file redirection
		PVOID OldValue = nullptr;
		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
		{
			APP_TRACE_LOG(LL_ERR, L"File redirection disable failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Setup launch parameters
		PROCESS_INFORMATION pi = { 0 };

		STARTUPINFOW si = { 0 };
		si.cb = sizeof(si);
		si.wShowWindow = SW_HIDE;
		si.dwFlags |= STARTF_USESTDHANDLES;
		si.hStdError = m_hOutWritePipe;
		si.hStdOutput = m_hOutWritePipe;
		si.hStdInput = m_hInReadPipe;

		// Copy cmdline to new pointer
		auto wszCmdLine = new wchar_t[MAX_PATH];
		memset(wszCmdLine, 0, MAX_PATH * sizeof(wchar_t));

		if (m_spClientCtx->wszCmdLine[0] != L'\0')
			wcsncpy(wszCmdLine, m_spClientCtx->wszCmdLine, wcslen(m_spClientCtx->wszCmdLine));

		if (bUnicode)
		{
			const std::wstring wstUnicodeFlag = xorstr_(L" /U");
			wcsncat(wszCmdLine, wstUnicodeFlag.c_str(), wstUnicodeFlag.size());
		}

		// Create child process
		const auto bSuccess = g_winAPIs->CreateProcessW(
			m_spClientCtx->wszAppPath[0] == L'\0' ? nullptr : m_spClientCtx->wszAppPath,
			wszCmdLine,
			nullptr, nullptr, TRUE, 0, nullptr, nullptr,
			&si, &pi
		);

		// Delete created mcdline ptr
		delete[] wszCmdLine;
		wszCmdLine = nullptr;

		// Revert file redirection
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);

		// Check create result
		if (!bSuccess)
		{
			APP_TRACE_LOG(LL_ERR, L"CreateProcessW('%ls' / '%ls') failed with error: %u", m_spClientCtx->wszAppPath, m_spClientCtx->wszCmdLine, g_winAPIs->GetLastError());
			return false;
		}
#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Child process: '%ls' ('%ls') [%u] created! Unicode: %d", m_spClientCtx->wszAppPath, m_spClientCtx->wszCmdLine, pi.dwProcessId, m_bUnicode ? 1 : 0);
#endif

		// Save child process handle
		m_hConsoleProc = pi.hProcess;

		// Close not required handles
		g_winAPIs->CloseHandle(pi.hThread);
		return true;
	}

	bool CRedirectedIOPipe::RunCommand(std::string& stCommand, bool bPrintRet)
	{
		auto bRet = false;

		APP_TRACE_LOG(LL_SYS, L"Command: %s execution started! Unicode: %d First: %d", stCommand.c_str(), m_bUnicode ? 1 : 0, m_bFirstExec ? 1 : 0);
		m_stLastCommand = stCommand;

		// Write command to pipe buffer
		if (!this->__Write(stCommand + xorstr_("\n")))
			return bRet;

		// Give some exec time penalty
		if (!__CheckPipeHasOutput(30000))
		{
			APP_TRACE_LOG(LL_ERR, L"Pipe read timeout!");
			return bRet;
		}

		if (bPrintRet)
			bRet = this->__ReadAndPrint();
		else
			bRet = this->__Read(stCommand);

		m_bFirstExec = false;
		APP_TRACE_LOG(LL_SYS, L"Command: execution completed with status: %d", bRet ? 1 : 0);
		return bRet;
	}

	bool CRedirectedIOPipe::__CheckPipeHasOutput(uint32_t nTimeout)
	{
		CStopWatch <std::chrono::milliseconds> timer;

		auto bRet = false;

		while (true)
		{
			g_winAPIs->Sleep(1000);

			if (timer.diff() > nTimeout)
				break;

			DWORD dwPipeBytesRead = 0;
			if (g_winAPIs->PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesRead, nullptr) && dwPipeBytesRead)
			{
				bRet = true;
				break;
			}
		}

		return bRet;
	}

	bool CRedirectedIOPipe::__FixCommandOutput(std::string& stBuffer)
	{
		if (stBuffer.empty())
			return false;

		if (m_bFirstExec)
		{
			// Start pos
			const std::string stStartPosSign = xorstr_(">") + m_stLastCommand + xorstr_("\n");
			const auto spos = stBuffer.find(stStartPosSign);
			if (spos == std::string::npos)
				return false;
			if (stBuffer.size() < spos + stStartPosSign.size())
				return false;

			stBuffer = stBuffer.substr(spos + stStartPosSign.size(), stBuffer.size());

			// End pos
			const std::string stEOLChar = xorstr_("\r\n");
			const auto epos = stBuffer.find_last_of(stEOLChar);
			if (epos == std::string::npos)
				return false;
			if (stBuffer.size() < epos + stEOLChar.size())
				return false;

			stBuffer = stBuffer.substr(0, epos - stEOLChar.size());
		}
		else
		{
			const std::string stStartPosSign = xorstr_("\r\n");
			const auto spos = stBuffer.find_first_of(stStartPosSign);
			if (spos == std::string::npos)
				return false;
			if (stBuffer.size() < spos + stStartPosSign.size())
				return false;

			stBuffer = stBuffer.substr(spos, stBuffer.size());
		}

		return !stBuffer.empty();
	}

	bool CRedirectedIOPipe::__ReadAndPrint()
	{
		auto bRet = false;

		if (!m_hOutReadPipe || m_hOutReadPipe == INVALID_HANDLE_VALUE)
		{
			APP_TRACE_LOG(LL_ERR, L"Output read pipe is not valid!");
			return bRet;
		}

		DWORD dwPipeBytesReadTotal = 0;
		while (true)
		{
			DWORD dwDummy = 0;
			if (!g_winAPIs->GetHandleInformation(m_hOutReadPipe, &dwDummy))
			{
				APP_TRACE_LOG(LL_ERR, L"Output read pipe handle is corrupted!");
				break;
			}

			DWORD dwPipeBytesReadCurrent = 0;
			if (!g_winAPIs->PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesReadCurrent, nullptr))
			{
				APP_TRACE_LOG(LL_ERR, L"PeekNamedPipe failed with error: %u", g_winAPIs->GetLastError());
				break;
			}

			dwPipeBytesReadTotal += dwPipeBytesReadCurrent;

			if (!dwPipeBytesReadTotal)
				break;

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Currently: %u bytes is readable in pipe, Total: %u bytes should read!", dwPipeBytesReadCurrent, dwPipeBytesReadTotal);
#endif

			auto nBufSize = dwPipeBytesReadTotal;
			auto pvBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
			if (!pvBuffer)
			{
				APP_TRACE_LOG(LL_ERR, L"Read buffer allocation with size: %u is failed with error: %d", nBufSize, errno);

				nBufSize = 2048;
				pvBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
				if (!pvBuffer)
				{
					APP_TRACE_LOG(LL_ERR, L"Read buffer allocation with size: %u is failed with error: %d", nBufSize, errno);
					break;
				}
			}
			memset(pvBuffer, 0, nBufSize);

			const auto dwReadSize = (dwPipeBytesReadTotal < nBufSize) ? dwPipeBytesReadTotal : nBufSize;
#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Read buffer size: %u", dwReadSize);
#endif

			DWORD dwFileBytesRead = 0;
			if (!g_winAPIs->ReadFile(m_hOutReadPipe, pvBuffer, dwReadSize, &dwFileBytesRead, nullptr))
			{
				APP_TRACE_LOG(LL_ERR, L"ReadFile failed with read size: %u error: %u", dwFileBytesRead, g_winAPIs->GetLastError());
				free(pvBuffer);
				break;
			}

			auto stBufferCopy = ""s;
			if (m_bUnicode)
			{
				const auto wstBufferCopy = std::wstring(reinterpret_cast<wchar_t*>(pvBuffer), dwFileBytesRead);
				stBufferCopy = stdext::to_ansi(wstBufferCopy);

#ifdef _DEBUG
				APP_TRACE_LOG(LL_SYS, L"Read unicode buffer: %ls", wstBufferCopy.c_str());
#endif
			}
			else
			{
				stBufferCopy = std::string(reinterpret_cast<char*>(pvBuffer), dwFileBytesRead);
			}

#ifdef _DEBUG
			APP_TRACE_LOG(LL_SYS, L"Read buffer: %s", stBufferCopy.c_str());
#endif

			if (!__FixCommandOutput(stBufferCopy))
			{
				APP_TRACE_LOG(LL_ERR, L"Read command output: %s is not valid", stBufferCopy.c_str());
				free(pvBuffer);
				break;
			}

			APP_TRACE_LOG(LL_SYS, L"%s\n", stBufferCopy.c_str());

			dwPipeBytesReadTotal -= dwFileBytesRead;
			bRet = true;

			free(pvBuffer);
			g_winAPIs->Sleep(1000);
		}

		return bRet;
	}

	bool CRedirectedIOPipe::__Read(std::string& stBuffer)
	{
		if (!m_hOutReadPipe || m_hOutReadPipe == INVALID_HANDLE_VALUE)
		{
			APP_TRACE_LOG(LL_ERR, L"Output read pipe is not valid!");
			return false;
		}

		constexpr auto nBufSize = 2048;
		const auto pvReadBuffer = calloc(nBufSize, m_bUnicode ? sizeof(wchar_t) : sizeof(char));
		if (!pvReadBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"Read buffer allocation failed!");
			return false;
		}
		memset(pvReadBuffer, 0, nBufSize);

		DWORD dwPipeBytesRead = 0;
		if (!g_winAPIs->PeekNamedPipe(m_hOutReadPipe, nullptr, 0, nullptr, &dwPipeBytesRead, nullptr))
		{
			APP_TRACE_LOG(LL_ERR, L"PeekNamedPipe failed with error: %u", g_winAPIs->GetLastError());
			free(pvReadBuffer);
			return false;
		}

		if (!dwPipeBytesRead)
		{
			APP_TRACE_LOG(LL_ERR, L"Have not any readable data in CMD pipe!");
			free(pvReadBuffer);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"%u bytes is readable in pipe!", dwPipeBytesRead);

		while (dwPipeBytesRead)
		{
			const auto dwReadSize = (dwPipeBytesRead < nBufSize) ? dwPipeBytesRead : nBufSize;

			DWORD dwFileBytesRead = 0;
			if (!g_winAPIs->ReadFile(m_hOutReadPipe, pvReadBuffer, dwReadSize, &dwFileBytesRead, nullptr))
			{
				free(pvReadBuffer);
				APP_TRACE_LOG(LL_ERR, L"ReadFile failed with read size: %u error: %u", dwFileBytesRead, g_winAPIs->GetLastError());
				return false;
			}

			auto stBufferCopy = ""s;
			if (m_bUnicode)
			{
				const auto wstBufferCopy = std::wstring(reinterpret_cast<wchar_t*>(pvReadBuffer), dwFileBytesRead);
				stBufferCopy = stdext::to_ansi(wstBufferCopy);
			}
			else
			{
				stBufferCopy = std::string(reinterpret_cast<char*>(pvReadBuffer), dwFileBytesRead);
			}

			stBuffer += stBufferCopy;
			dwPipeBytesRead -= dwFileBytesRead;
		}

#ifdef _DEBUG
		APP_TRACE_LOG(LL_SYS, L"Read succesfully completed! Buffer: %s (%u)", stBuffer.c_str(), stBuffer.size());
#endif
		free(pvReadBuffer);
		return __FixCommandOutput(stBuffer);
	}

	bool CRedirectedIOPipe::__Write(const std::string& stBuffer)
	{
		if (!m_hInWritePipe || m_hInWritePipe == INVALID_HANDLE_VALUE)
		{
			APP_TRACE_LOG(LL_ERR, L"Input write pipe is not valid!");
			return false;
		}

		g_winAPIs->SetLastError(0);

		DWORD dwWrited = 0;
		const auto bRet = g_winAPIs->WriteFile(m_hInWritePipe, stBuffer.c_str(), stBuffer.size(), &dwWrited, nullptr);

#ifdef _DEBUG
		const auto stLogBuffer = fmt::format(
			"WriteFile completed! Buffer: {0}({1}) Writed: {2} Completed: {3} Last error: {4}",
			stBuffer, stBuffer.size(), dwWrited, bRet, g_winAPIs->GetLastError()
		);
		APP_TRACE_LOG(bRet ? LL_SYS : LL_ERR, L"%s", stLogBuffer.c_str());
#endif

		return bRet;
	}
}
