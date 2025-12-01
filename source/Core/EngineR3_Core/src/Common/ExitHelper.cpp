#include "../../include/PCH.hpp"
#include "../../include/ExitHelper.hpp"
#include "../../include/SafeExecutor.hpp"

namespace NoMercyCore
{
	static std::atomic_bool gs_abIsErrorTriggered = false;

	void SetErrorTriggered()
	{
		gs_abIsErrorTriggered.store(true);
	}

	// See: ECoreErrorCodes
	void OnPreFail(uint8_t nAppType, const ECoreErrorCodes dwErrorCode, const uint32_t dwErrorSubCode, const std::wstring& wstMessage)
	{
//		__PROTECTOR_START__("pre_exit");

#ifdef _DEBUG
		if (IsDebuggerPresent())
			DebugBreak();
#endif

		if (gs_abIsErrorTriggered.load())
			return;
		gs_abIsErrorTriggered.store(true);

		const auto bHasCoreInstance = NoMercyCore::CApplication::InstancePtr() != nullptr;

		uint32_t dwInitErrCode = 0, dwInitErrSubCode = 0;
		if (bHasCoreInstance)
		{
			dwInitErrCode = NoMercyCore::CApplication::Instance().GetInitErrorCode();
			dwInitErrSubCode = NoMercyCore::CApplication::Instance().GetInitErrorSubCode();

			if (!nAppType)
				nAppType = NoMercyCore::CApplication::Instance().GetAppType();
		}

		if (!dwInitErrCode)
			dwInitErrCode = dwErrorSubCode;
		
		const auto fnGetLastError = LI_FN(GetLastError).forwarded_safe();

		wchar_t wszExecutable[MAX_PATH]{ L'\0' };
		const auto fnGetModuleName = LI_FN(GetModuleFileNameW).forwarded_safe();
		if (!fnGetModuleName || !fnGetModuleName(nullptr, wszExecutable, MAX_PATH))
			_snwprintf(wszExecutable, MAX_PATH, xorstr_(L"'GetModuleFileNameA failed with error: %u'"), fnGetLastError ? fnGetLastError() : 0);

		std::wstring wstErrMessage = fmt::format(
			xorstr_(L"An error occured in NoMercy core initilization!\n\nVersion: {0} - App: {1} - Phase: {2}(Pre)\nError ID: {3}#{4} / {5}#{6}\nMessage: {7}\nExecutable: {8} ({9})"),
			stdext::to_wide(__PRODUCT_VERSION__), nAppType, EPhase::PHASE_PRE,
			dwErrorCode, fnGetLastError ? fnGetLastError() : 0,
			dwInitErrCode, dwInitErrSubCode,
			wstMessage,
			wszExecutable, HandleToUlong(NtCurrentProcessId())
		);

		LogfW(CUSTOM_LOG_FILENAME_W, wstErrMessage.c_str());

		ServiceMessageBox(xorstr_(L"NoMercy Fatal Error"), wstErrMessage.c_str(), MB_ICONERROR);

		if (bHasCoreInstance)
			NoMercyCore::CApplication::Instance().InvokeFatalErrorCallback();

		if (stdext::is_debug_env())
			std::abort();
		else
			std::exit(EXIT_FAILURE);

//		__PROTECTOR_END__("pre_exit");
	}
};
