#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	void IScanner::OnWatcherWindowScan(HWND hWnd, uint32_t nReason)
	{
		// APP_TRACE_LOG(LL_SYS, L"New window detected! Wnd: %p Reason: %u", hWnd, nReason);

		if (this->WindowScanner())
		{
			this->WindowScanner()->ScanAsync(hWnd);
		}
	}
};
