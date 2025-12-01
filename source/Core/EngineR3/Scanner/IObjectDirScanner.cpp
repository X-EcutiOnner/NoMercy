#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"





namespace NoMercy
{
	IObjectDirectoryScanner::IObjectDirectoryScanner()
	{
	}
	IObjectDirectoryScanner::~IObjectDirectoryScanner()
	{
	}

	std::wstring GetSymbolicLinkFromName(const std::wstring& directory, const std::wstring& name)
	{
		UNICODE_STRING strDir{ 0 };
		g_winAPIs->RtlInitUnicodeString(&strDir, directory.c_str());

		OBJECT_ATTRIBUTES attrDir{ 0 };
		InitializeObjectAttributes(&attrDir, &strDir, 0, nullptr, nullptr);

		NTSTATUS ntStatus = 0;
		HANDLE hRoot = nullptr;
		if (!NT_SUCCESS(ntStatus = g_winAPIs->NtOpenDirectoryObject(&hRoot, GENERIC_READ, &attrDir)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtOpenDirectoryObject failed with error: %p", ntStatus);
			return L"";
		}

		UNICODE_STRING str{ 0 };
		g_winAPIs->RtlInitUnicodeString(&str, name.c_str());

		OBJECT_ATTRIBUTES attr{ 0 };
		InitializeObjectAttributes(&attr, &str, 0, hRoot, nullptr);

		HANDLE hLink = nullptr;
		if (!NT_SUCCESS(ntStatus = g_winAPIs->NtOpenSymbolicLinkObject(&hLink, GENERIC_READ, &attr)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtOpenSymbolicLinkObject failed with error: %p", ntStatus);
			return L"";
		}

		WCHAR buffer[512] = { 0 };

		UNICODE_STRING target{ 0 };
		g_winAPIs->RtlInitUnicodeString(&target, buffer);
		target.MaximumLength = sizeof(buffer);

		ULONG len = 0;
		if (!NT_SUCCESS(ntStatus = g_winAPIs->NtQuerySymbolicLinkObject(hLink, &target, &len)))
		{
			APP_TRACE_LOG(LL_ERR, L"NtQuerySymbolicLinkObject failed with error: %p", ntStatus);
			return L"";
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hLink);
		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hRoot);

		return std::wstring(target.Buffer, target.Length / sizeof(WCHAR));
	}

	bool IObjectDirectoryScanner::EnumerateObjectDirectory(const std::wstring& wstRootDirName, std::function<bool(OBJECT_DIRECTORY_INFORMATION)> cb)
	{
		if (wstRootDirName.empty() || !cb)
			return false;

		UNICODE_STRING uniString;
		g_winAPIs->RtlInitUnicodeString(&uniString, wstRootDirName.c_str());

		OBJECT_ATTRIBUTES oa;
		InitializeObjectAttributes(&oa, &uniString, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE hDirectory = nullptr;
		auto ntStatus = g_winAPIs->NtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &oa);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtOpenDirectoryObject(%ls) failed with error: %p", wstRootDirName.c_str(), ntStatus);
			if (IS_VALID_HANDLE(hDirectory))
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDirectory);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Target object directory: %ls", wstRootDirName.c_str());

		const auto ullBufferSize = 1 << 17;
		auto lpBuffer = (POBJECT_DIRECTORY_INFORMATION)CMemHelper::Allocate(ullBufferSize);
		if (!lpBuffer)
		{
			APP_TRACE_LOG(LL_ERR, L"lpBuffer allocation failed with error: %p", g_winAPIs->GetLastError());
			if (IS_VALID_HANDLE(hDirectory))
				NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDirectory);
			return false;
		}

		BOOLEAN firstEntry = TRUE;
		ULONG rlen = 0;
		ULONG idx = 0;
		ULONG start = 0;
		do
		{
			ntStatus = g_winAPIs->NtQueryDirectoryObject(hDirectory, lpBuffer, ullBufferSize, FALSE, firstEntry, &idx, &rlen);
			if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_NO_MORE_ENTRIES)
			{
				APP_TRACE_LOG(LL_ERR, L"NtQueryDirectoryObject failed with error: %p", ntStatus);
			}
			else if (ntStatus == STATUS_NO_MORE_ENTRIES)
			{
				break;
			}
			
			for (ULONG i = 0; i < idx - start; i++)
			{
				const auto directoryInfo = lpBuffer[i];
				if (!cb(directoryInfo))
					break;
			}

			start = idx;
			if (firstEntry)
				firstEntry = FALSE;
		} while (true);

		CMemHelper::Free(lpBuffer);

		if (IS_VALID_HANDLE(hDirectory))
			NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->SafeCloseHandle(hDirectory);

		return true;
	}

	bool IObjectDirectoryScanner::IsScanned(std::shared_ptr <SObjectDirectoryScanContext> ctx)
	{
		return CApplication::Instance().ScannerInstance()->IsCachedScanObject(SCAN_CACHE_OBJECT_DIRECTORY, ctx->wszDirectory);
	}
	void IObjectDirectoryScanner::AddScanned(std::shared_ptr <SObjectDirectoryScanContext> ctx)
	{
		CApplication::Instance().ScannerInstance()->AddCachedScanObject(SCAN_CACHE_OBJECT_DIRECTORY, ctx->wszDirectory);
	}
	
	void IObjectDirectoryScanner::ScanSync(std::shared_ptr <SObjectDirectoryScanContext> ctx)
	{		
		APP_TRACE_LOG(LL_SYS, L"Target: %ls - %ls", ctx->wszDirectory.c_str(), ctx->wszType.c_str());

		// TODO
	}

	bool IObjectDirectoryScanner::ScanAll()
	{		
		static const auto wstRoot = L"\\"s;

		EnumerateObjectDirectory(wstRoot, [&](OBJECT_DIRECTORY_INFORMATION dir) {
			const auto ctx = stdext::make_shared_nothrow<SObjectDirectoryScanContext>();
			if (IS_VALID_SMART_PTR(ctx))
			{
				ctx->wszRootDirectory = wstRoot;
				ctx->wszDirectory = std::wstring(dir.Name.Buffer, dir.Name.Length);
				ctx->wszType = std::wstring(dir.TypeName.Buffer, dir.TypeName.Length);

				ScanAsync(ctx);
			}
			return true;
		});

		return true;
	}
};
