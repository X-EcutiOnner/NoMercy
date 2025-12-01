#pragma once
#include "ErrorIDs.hpp"

namespace NoMercyCore
{
	void SetErrorTriggered();
	void OnPreFail(uint8_t nAppType, const ECoreErrorCodes dwErrorCode, const uint32_t dwErrorSubCode = 0, const std::wstring& wstMessage = L"");
};
