#pragma once
#include "../../EngineR3_Core/include/ErrorIDs.hpp"
#include "../../EngineR3_Core/include/InitilizationManager.hpp"

namespace NoMercyCore
{
	class CErrorMessageHelper : public CSingleton <CErrorMessageHelper>
	{
	public:
		CErrorMessageHelper();
		virtual ~CErrorMessageHelper();

		std::wstring PrepareTelemetryLocalizedErrorMessage(const std::wstring& wstTitle, uint32_t nErrCode, uint32_t nErrSubCode, uint32_t nPhaseCode);
		std::wstring PrepareErrorMessage(EPhase nAppPhase, ELocalizationPhase nI18nPhase, uint32_t dwErrorCode, uint32_t dwSystemErrorCode, void* pParam = nullptr);
	};
};
