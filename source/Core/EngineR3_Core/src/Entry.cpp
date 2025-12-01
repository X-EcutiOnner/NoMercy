#include "../include/Index.hpp"
#include "../include/Application.hpp"

namespace NoMercyCore
{
	static CApplication* gs_pkApplicationPtr = nullptr;

	bool CCoreIndex::Init(const uint8_t nAppType, const HINSTANCE hInstance, LPCVOID c_lpModuleInfo)
	{
		if (gs_pkApplicationPtr)
			return false;

		gs_pkApplicationPtr = new(std::nothrow) CApplication(nAppType, hInstance, c_lpModuleInfo);
		if (!gs_pkApplicationPtr || !CApplication::InstancePtr())
			return false;

		return gs_pkApplicationPtr->Initialize();
	}

	void CCoreIndex::Release()
	{
		if (!gs_pkApplicationPtr)
			return;

		gs_pkApplicationPtr->Finalize();

		delete gs_pkApplicationPtr;
		gs_pkApplicationPtr = nullptr;
	}

	bool CCoreIndex::IsInitialized()
	{
		if (gs_pkApplicationPtr && CApplication::InstancePtr())
			return gs_pkApplicationPtr->IsInitialized();

		return false;
	}

	std::tuple <DWORD, DWORD> CCoreIndex::GetErrorCodes()
	{
		if (gs_pkApplicationPtr && CApplication::InstancePtr())
			return std::make_tuple(gs_pkApplicationPtr->GetInitErrorCode(), gs_pkApplicationPtr->GetInitErrorSubCode());

		return std::make_tuple(0, 0);
	}
}
