#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../../EngineR3_Core/include/Pe.hpp"


namespace NoMercy
{
	inline void CheckHiddenFile(const std::wstring& stDriverName)
	{
		// TODO
	}

	inline void CheckCertificate(const std::wstring& stDriverName)
	{
		// TODO
		// blacklist hash/name
		// check EV signs for 10 & 11 "Microsoft Windows Hardware Compatibility Publisher" on signature issuer list
	}

	inline void CheckSuspectedImports(const std::wstring& stDriverName)
	{
		static const auto vecSearchedImports = {
			xorstr_(L"MmMapIoSpace"),
			xorstr_(L"MmMapIoSpaceEx"),
			xorstr_(L"MmGetPhysicalAddress"),
			xorstr_(L"MmMapLockedPages"),
			xorstr_(L"MmMapLockedPagesSpecifyCache"),
			xorstr_(L"MmMapLockedPagesWithReservedMapping")
		};

		if (!std::filesystem::exists(stDriverName))
			return;

		auto fp = msl::file_ptr(stDriverName, xorstr_(L"rb"));
		if (!fp)
			return;

		const auto buffer = fp.string_read();
		if (buffer.empty())
			return;

		const auto pe = Pe::PeNative::fromFile(buffer.data());
		if (!pe.valid())
			return;

		for (const auto& imp : pe.imports())
		{
			if (!imp.valid())
				continue;

			const auto stImpLibName = stdext::to_lower_ansi(imp.libName());
			if (stImpLibName != xorstr_("ntoskrnl.exe"))
				continue;

			for (const auto& fn : imp)
			{
				if (fn.type() != Pe::ImportType::name)
					continue;

				const std::wstring stImpName = stdext::to_wide(fn.name()->Name);
				if (stImpName.empty())
					continue;

				if (!stdext::in_vector(vecSearchedImports, stImpName))
					continue;

#ifdef _DEBUG
				SCANNER_LOG(LL_CRI, L"Suspected import found at: %s:%s", stDriverName.c_str(), stImpName.c_str());
#endif			
			}

		}
	}

	inline void CheckKernelCoreModule(const std::wstring& stDriverName)
	{
		// TODO
				// Check exist ntoskrnl in name
				// Check path "\System32\Drivers\" "\SystemRoot\system32\drivers\"
				// check CheckSumMappedFile
				// check sfc protected api
				// check digital sign
				// check digital sign issuer is microsoft
				// check file description(author) "Microsoft Windows"
				// check digital signature timestamp
	}

	inline void CheckUnlinkedDrivers(const std::vector <std::wstring>& vecLinkedDrivers)
	{
		// compare with Win32_SystemDriver WMI
	}

	IDriverScanner::IDriverScanner()
	{
	}
	IDriverScanner::~IDriverScanner()
	{
	}

	bool IDriverScanner::IsScanned(std::wstring stDriverPathName)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_DRIVER, stDriverPathName);
	}
	void IDriverScanner::AddScanned(std::wstring stDriverPathName)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_DRIVER, stDriverPathName);
	}

	void IDriverScanner::ScanSync(std::wstring stDriverPathName)
	{
		if (stDriverPathName.empty())
			return;

		SCANNER_LOG(LL_SYS, L"Driver scanner has been started! Target: %s", stDriverPathName.c_str());

		stDriverPathName = CApplication::Instance().ScannerInstance()->PatchFileName(stDriverPathName);

		SCANNER_LOG(LL_SYS, L"Fixed file name: %s", stDriverPathName.c_str());

		if (IsScanned(stDriverPathName))
		{
			SCANNER_LOG(LL_SYS, L"Driver: %s already scanned!", stDriverPathName.c_str());
			return;
		}
		AddScanned(stDriverPathName);

		CheckHiddenFile(stDriverPathName);
		CheckCertificate(stDriverPathName);

		CApplication::Instance().ScannerInstance()->FileScanner()->Scan(stDriverPathName, FILE_SCAN_TYPE_DRIVER);
	}

	bool IDriverScanner::ScanAll()
	{
		SCANNER_LOG(LL_SYS, L"Driver scanner routine started!");

		std::vector <std::wstring> vecLinkedDrivers;
		CApplication::Instance().ScannerInstance()->EnumerateDrivers([&](std::shared_ptr <SDriverScanContext> ctx) -> bool {
			if (IS_VALID_SMART_PTR(ctx))
			{
				if (ctx->nIdx == 0 && (ctx->usLoadOrderIndex != 0 || ctx->usInitOrderIndex != 0))
				{
					SCANNER_LOG(LL_ERR, L"Core driver: %s has invalid load order index: %u or init order index: %u",
						ctx->wstExecutable.c_str(), ctx->usLoadOrderIndex, ctx->usInitOrderIndex
					);

					const auto nSusIndex = ctx->usLoadOrderIndex != 0 ? ctx->usLoadOrderIndex : ctx->usInitOrderIndex;
					CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_CORE_DRIVER_INVALID_INDEX, nSusIndex, ctx->wstExecutable);
				}

				CheckKernelCoreModule(ctx->wstExecutable);

				vecLinkedDrivers.emplace_back(ctx->wstExecutable);
				ScanAsync(ctx->wstExecutable);
			}
			return true;
		});

		CheckUnlinkedDrivers(vecLinkedDrivers);

		vecLinkedDrivers.clear();
		SCANNER_LOG(LL_SYS, L"Driver scanner routine completed!");
		return true;
	}

	bool IScanner::EnumerateDrivers(std::function<bool(std::shared_ptr <SDriverScanContext>)> cb)
	{
		SCANNER_LOG(LL_SYS, L"Driver enum routine started!");

		const auto dwBufferSize = 1024 * 1024;
		auto lpModuleBuffer = reinterpret_cast<RTL_PROCESS_MODULES*>(CMemHelper::Allocate(dwBufferSize));
		if (!lpModuleBuffer)
		{
			SCANNER_LOG(LL_ERR, L"lpModuleBuffer allocation failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		const auto ntStatus = g_winAPIs->NtQuerySystemInformation(SystemModuleInformation, lpModuleBuffer, dwBufferSize, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			SCANNER_LOG(LL_ERR, L"NtQuerySystemInformation failed with error: %p", ntStatus);
			CMemHelper::Free(lpModuleBuffer);
			return false;
		}

		for (std::size_t i = 0; i < lpModuleBuffer->NumberOfModules; i++)
		{
			auto& c_lpCurrentDriver = lpModuleBuffer->Modules[i];

			auto ctx = stdext::make_shared_nothrow<SDriverScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->nIdx = i;
				ctx->pMappedBase = c_lpCurrentDriver.MappedBase;
				ctx->pImageBase = c_lpCurrentDriver.ImageBase;
				ctx->ulImageSize = c_lpCurrentDriver.ImageSize;
				ctx->ulFlags = c_lpCurrentDriver.Flags;
				ctx->usLoadOrderIndex = c_lpCurrentDriver.LoadOrderIndex;
				ctx->usInitOrderIndex = c_lpCurrentDriver.InitOrderIndex;
				ctx->wstExecutable = stdext::to_wide((const char*)c_lpCurrentDriver.FullPathName);

#ifdef _DEBUG
				APP_TRACE_LOG(LL_SYS, L"[%u] (%u/%u) %p/%p (%u) F:%u >> %s",
					i, c_lpCurrentDriver.LoadOrderIndex, c_lpCurrentDriver.InitOrderIndex,
					c_lpCurrentDriver.MappedBase, c_lpCurrentDriver.ImageBase, c_lpCurrentDriver.ImageSize,
					c_lpCurrentDriver.Flags, ctx->wstExecutable.c_str()
				);
#endif

				if (!cb(ctx))
					break;
			}
		}

		if (lpModuleBuffer)
		{
			CMemHelper::Free(lpModuleBuffer);
			lpModuleBuffer = nullptr;
		}

		SCANNER_LOG(LL_SYS, L"Driver enum routine completed!");
		return true;
	}
};
