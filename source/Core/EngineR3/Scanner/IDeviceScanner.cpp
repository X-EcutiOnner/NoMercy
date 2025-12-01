#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"

namespace NoMercy
{
	void IScanner::CheckDevices()
	{
		auto dev_name = (LPWSTR)CMemHelper::Allocate(0x20000);
		if (!dev_name)
			return;
		const auto ptr_copy = dev_name;

		const auto ret = g_winAPIs->QueryDosDeviceW(0, dev_name, 0x20000);
		if (!ret)
		{
			CMemHelper::Free(dev_name);
			return;
		}

		size_t total_len = 0;
		while (total_len < ret)
		{
			const auto dev_path = (LPWSTR)CMemHelper::Allocate(0x2000);
			if (!dev_path)
				continue;

			const auto ret2 = g_winAPIs->QueryDosDeviceW(dev_name, dev_path, 0x2000);
			if (!ret2)
			{
				CMemHelper::Free(dev_path);
				break;
			}

			// APP_TRACE_LOG(LL_SYS, L"%s - %s", dev_name, dev_path);
			// TODO: Scan device

			const auto len = wcslen(dev_name) + 1;
			dev_name += len;
			total_len += len;

			CMemHelper::Free(dev_path);
		}

		CMemHelper::Free(ptr_copy);
	}
};
