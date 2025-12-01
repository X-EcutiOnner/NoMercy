#include "../../include/PCH.hpp"
#include "../../include/ErrorMessageHelper.hpp"

namespace NoMercyCore
{
	CErrorMessageHelper::CErrorMessageHelper()
	{
	}
	CErrorMessageHelper::~CErrorMessageHelper()
	{
	}

	std::wstring CErrorMessageHelper::PrepareTelemetryLocalizedErrorMessage(const std::wstring& wstTitle, uint32_t nErrCode, uint32_t nErrSubCode, uint32_t nPhaseCode)
	{
		auto fnPhaseToI18nPhase = [](const uint32_t nPhase) {
			const auto phase = static_cast<EPhase>(nPhase);
			switch (phase)
			{
			case EPhase::PHASE_PRE:
				return ELocalizationPhase::I18M_PHASE_PRE;

			case EPhase::PHASE_INIT:
				return ELocalizationPhase::I18N_PHASE_INIT;

			case EPhase::PHASE_POST:
				return ELocalizationPhase::I18N_PHASE_POST;

			default:
				return ELocalizationPhase::I18N_PHASE_NULL;
			}
		};

		if (!nErrCode || !nPhaseCode)
			return wstTitle;

		auto wstLocalizedMessage = L""s;
		if (NoMercyCore::CApplication::InstancePtr() && IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().InitilizationManagerInstance()))
		{
			const auto kPhase = fnPhaseToI18nPhase(nPhaseCode);
			wstLocalizedMessage = NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->GetI18nW(kPhase, nErrCode, nErrSubCode);
			APP_TRACE_LOG(LL_SYS, L"[%u/%u] %u/%u >> '%s'", nPhaseCode, kPhase, nErrCode, nErrSubCode, wstLocalizedMessage.c_str());
		}
		APP_TRACE_LOG(LL_WARN, L"Localized message: %s", wstLocalizedMessage.c_str());

		wstLocalizedMessage = fmt::format(xorstr_(L"{0} {1}"), wstTitle, wstLocalizedMessage);
		APP_TRACE_LOG(LL_WARN, L"Final message: %s", wstLocalizedMessage.c_str());

		return wstLocalizedMessage;
	}

	std::wstring CErrorMessageHelper::PrepareErrorMessage(EPhase nAppPhase, ELocalizationPhase nI18nPhase, uint32_t dwErrorCode, uint32_t dwSystemErrorCode, void* pParam)
	{
#ifdef _DEBUG
		if (IsDebuggerPresent())
			DebugBreak();
#endif

		const auto wstVersion = stdext::to_wide(__PRODUCT_VERSION__);
		const auto nAppType = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();
		const auto wstAppType = GetAppTypeNameW(nAppType);

		APP_TRACE_LOG(LL_WARN, L"Phase: %u/%u Error: %u/%u Param: %p Version: %s App: %u (%s)",
			nAppPhase, nI18nPhase, dwErrorCode, dwSystemErrorCode, pParam, wstVersion.c_str(), nAppType, wstAppType.c_str()
		);

		auto wstBuffer = L""s;
		
		auto wstLocalizedMessage = L""s;
		if (NoMercyCore::CApplication::InstancePtr() && IS_VALID_SMART_PTR(NoMercyCore::CApplication::Instance().InitilizationManagerInstance()))
		{
			wstLocalizedMessage = NoMercyCore::CApplication::Instance().InitilizationManagerInstance()->GetI18nW(nI18nPhase, dwErrorCode, dwSystemErrorCode);
			APP_TRACE_LOG(LL_SYS, L"[%u/%u] %u/%u >> '%s'", nAppPhase, nI18nPhase, dwErrorCode, dwSystemErrorCode, wstLocalizedMessage.c_str());
		}
		APP_TRACE_LOG(LL_WARN, L"Localized message: %s", wstLocalizedMessage.c_str());

		if (!wstLocalizedMessage.empty())
		{
			if (pParam)
			{
				// One additional format param
				if ((nAppPhase == EPhase::PHASE_POST && dwErrorCode == EXIT_ERR_WEBSOCKET_ERROR_MESSAGE) ||
					(nAppPhase == EPhase::PHASE_POST && dwErrorCode == EXIT_ERR_UNALLOWED_TOOL_DETECTED))
				{
					wstLocalizedMessage = fmt::format(wstLocalizedMessage, (const wchar_t*)pParam);
				}
			}

			try
			{
				wstBuffer = fmt::format(xorstr_(L"{0}\n\nApp: {1}({2})\nVersion: {3} - Phase: {4}\nError ID: {5} System error: {6}"),
					wstLocalizedMessage, nAppType, wstAppType, wstVersion, nAppPhase, dwErrorCode, dwSystemErrorCode
				);
				return wstBuffer;
			}
			catch (const std::exception& ex)
			{
				APP_TRACE_LOG(LL_CRI, L"(%u - %u) Format exception: %hs", nI18nPhase, dwErrorCode, ex.what());
			}
			catch (...)
			{
				APP_TRACE_LOG(LL_CRI, L"Unhandled exception");
			}
		}

		APP_TRACE_LOG(LL_WARN, L"Created buffer: %s", wstBuffer.c_str());

		if (wstBuffer.empty())
		{
			wstBuffer = fmt::format(
				xorstr_(L"Unknown error handled!\n\nApp: {0}({1})\nVersion: {2} - Phase: {3}\nError ID: {4} System error: {5}"),
				nAppType, wstAppType, wstVersion, nAppPhase, dwErrorCode, dwSystemErrorCode
			);
		}
		APP_TRACE_LOG(LL_WARN, L"Final buffer: %s", wstBuffer.c_str());

		return wstBuffer;
	}
};
