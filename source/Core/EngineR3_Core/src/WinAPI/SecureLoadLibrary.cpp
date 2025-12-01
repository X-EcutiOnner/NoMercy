#include "../../include/PCH.hpp"
#include "../../include/SecureLoadLibrary.hpp"
#include "../../include/PEHelper.hpp"



namespace NoMercyCore
{
	CSecureLoadLibrary::CSecureLoadLibrary()
	{
	}
	CSecureLoadLibrary::~CSecureLoadLibrary()
	{
	}

	bool CSecureLoadLibrary::Load(const std::wstring& wstName, ESLLLoadType eLoadType)
	{
		APP_TRACE_LOG(LL_SYS, L"Module: %s loading with type: %u", wstName.c_str(), eLoadType);

		std::wstring wstFixedModuleName = stdext::to_lower_wide(wstName);
		if (stdext::is_wow64())
		{
			const auto wstSysPath = stdext::to_lower_wide(CApplication::Instance().DirFunctionsInstance()->SystemPath());
			const auto wstSysWow64Path = stdext::to_lower_wide(CApplication::Instance().DirFunctionsInstance()->SystemPath2());

			if (stdext::starts_with(wstFixedModuleName, wstSysPath))
				wstFixedModuleName = stdext::replace(wstFixedModuleName, wstSysPath, wstSysWow64Path);

			APP_TRACE_LOG(LL_SYS, L"Fixed module name: %s", wstFixedModuleName.c_str());
		}

		if (!std::filesystem::exists(wstFixedModuleName))
		{
			APP_TRACE_LOG(LL_ERR, L"Target file: %s does not exist!", wstFixedModuleName.c_str());
			return false;
		}

		const auto wstModuleName = CApplication::Instance().DirFunctionsInstance()->GetNameFromPath(wstFixedModuleName);
		if (wstModuleName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Target file: %s name parse failed!", wstFixedModuleName.c_str());
			return false;
		}
		
		switch (eLoadType)
		{
		case ESLLLoadType::LOAD_FROM_FILE:
			return this->LoadFromFile(wstFixedModuleName, wstModuleName);
		case ESLLLoadType::LOAD_FROM_MEMORY:
			return this->LoadFromMemory(wstFixedModuleName, wstModuleName);
		default:
			return false;
		};
	}

	bool CSecureLoadLibrary::Release(const std::wstring& stName)
	{
		if (stName.empty())
		{
			for (const auto& pkModuleCtx : m_vMappedFiles)
			{
				if (!pkModuleCtx.wstOriginalName.empty()) // prevent than infinite loop
					this->Release(pkModuleCtx.wstOriginalName);
			}

			// APP_TRACE_LOG(LL_WARN, L"Remaining size: %u", m_vMappedFiles.size());
			return true;
		}
		else
		{
			if (auto ctx = this->Get(stName))
			{
				if (ctx->bIsReleased)
					return true;
				
				const auto ntStatus = g_winAPIs->NtUnmapViewOfSection(NtCurrentProcess(), ctx->lpMappedData);
				// APP_TRACE_LOG(LL_ERR, L"%s unmap completed with status: %p", stName.c_str(), ntStatus);

				if (ctx->bIsLoadedFromFile)
				{
					const auto bDeleteRet = g_winAPIs->DeleteFileW(ctx->wstName.c_str());
					// APP_TRACE_LOG(LL_ERR, L"%s (%s) delete completed with status: %d (%u)", ctx->stName.c_str(), stName.c_str(), g_winAPIs->GetLastError());
				}

				ctx->bIsReleased = true;
				return true;
			}
			else
			{
				// APP_TRACE_LOG(LL_ERR, L"%s is not known secure module name", stName.c_str());
			}
		}

		return false;
	}

	bool CSecureLoadLibrary::LoadFromMemory(const std::wstring& stName, const std::wstring& wstModuleName)
	{
		UNICODE_STRING KnownDllName{ 0 };
#ifdef _WIN64
		auto ntStatus = g_winAPIs->RtlInitUnicodeStringEx(&KnownDllName, xorstr_(L"\\KnownDlls"));
#else
		auto ntStatus = g_winAPIs->RtlInitUnicodeStringEx(&KnownDllName, xorstr_(L"\\KnownDlls32"));
#endif
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlInitUnicodeStringEx failed with status: 0x%X", ntStatus);
			return false;
		}

		OBJECT_ATTRIBUTES KnownDllAttributes{ 0 };
		InitializeObjectAttributes(&KnownDllAttributes, &KnownDllName, OBJ_CASE_INSENSITIVE, NULL, NULL);

		HANDLE KnownDllDirectoryHandle = NULL;
		ntStatus = g_winAPIs->NtOpenDirectoryObject(&KnownDllDirectoryHandle, DIRECTORY_TRAVERSE | DIRECTORY_QUERY, &KnownDllAttributes);
		if (!NT_SUCCESS(ntStatus) || !KnownDllDirectoryHandle)
		{
			APP_TRACE_LOG(LL_ERR, L"NtOpenDirectoryObject failed with status: 0x%X", ntStatus);
			return false;
		}

		UNICODE_STRING SectionName{ 0 };
		ntStatus = g_winAPIs->RtlInitUnicodeStringEx(&SectionName, wstModuleName.c_str());
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"RtlInitUnicodeStringEx failed with status: 0x%X", ntStatus);
			g_winAPIs->NtClose(KnownDllDirectoryHandle);
			return false;
		}

		OBJECT_ATTRIBUTES SectionAttributes{ 0 };
		InitializeObjectAttributes(&SectionAttributes, &SectionName, OBJ_CASE_INSENSITIVE, KnownDllDirectoryHandle, NULL);

		HANDLE SectionHandle = NULL;
		ntStatus = g_winAPIs->NtOpenSection(&SectionHandle, SECTION_MAP_EXECUTE | SECTION_MAP_READ | SECTION_QUERY, &SectionAttributes);
		if (!NT_SUCCESS(ntStatus) || !SectionHandle)
		{
			if (ntStatus == STATUS_OBJECT_NAME_NOT_FOUND)
			{
				APP_TRACE_LOG(LL_WARN, L"%ls!%s is not linked in KnownDlls directory!", wstModuleName.c_str(), stName.c_str());
			}
			else
			{
				APP_TRACE_LOG(LL_ERR, L"NtOpenSection failed with status: %p", ntStatus);
			}
			g_winAPIs->NtClose(KnownDllDirectoryHandle);
			return false;
		}

		PVOID SectionBase = NULL;
		SIZE_T SectionSize = 0;
		ntStatus = g_winAPIs->NtMapViewOfSection(SectionHandle, NtCurrentProcess(), &SectionBase, 0, 0, NULL, &SectionSize, ViewUnmap, 0, PAGE_READONLY);
		if (!NT_SUCCESS(ntStatus))
		{
			APP_TRACE_LOG(LL_ERR, L"NtMapViewOfSection failed with status: 0x%X", ntStatus);
			g_winAPIs->NtClose(SectionHandle);
			g_winAPIs->NtClose(KnownDllDirectoryHandle);
			return false;
		}

		SMappedFileCtx ctx{ };
		ctx.bIsLoadedFromFile = false;
		ctx.wstOriginalName = stdext::to_lower_wide(stName);
		ctx.wstName = stName;
		ctx.lpMappedData = (uint8_t*)SectionBase;
		ctx.nMappedSize = (uint32_t)SectionSize;
		ctx.lpRawData = (uint8_t*)SectionBase;
		ctx.nRawSize = (uint64_t)SectionSize;
		
		m_vMappedFiles.emplace_back(ctx);

		g_winAPIs->NtClose(SectionHandle);
		g_winAPIs->NtClose(KnownDllDirectoryHandle);
		return true;
	}
	bool CSecureLoadLibrary::LoadFromFile(const std::wstring& stName, const std::wstring& stModuleName)
	{
		const auto stTempFileName = CApplication::Instance().DirFunctionsInstance()->CreateTempFileName(xorstr_(L"nm_sll"));
		if (stTempFileName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"Creae temp filename failed! Last error: %u", g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->CopyFileW(stName.c_str(), stTempFileName.c_str(), FALSE))
		{
			APP_TRACE_LOG(LL_ERR, L"CopyFileW('%s' -> '%s') failed with error: %u", stName.c_str(), stTempFileName.c_str(), g_winAPIs->GetLastError());
			return false;
		}

		if (!g_winAPIs->SetFileAttributesW(stTempFileName.c_str(), FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_HIDDEN))
		{
			APP_TRACE_LOG(LL_ERR, L"SetFileAttributesW('%s') failed with error: %u", stTempFileName.c_str(), g_winAPIs->GetLastError());
			return false;
		}

		if (!this->Map(stName, stTempFileName))
		{
			APP_TRACE_LOG(LL_ERR, L"Mapping file: %s failed! Last error: %u", stTempFileName.c_str(), g_winAPIs->GetLastError());
			return false;
		}

		const auto lpMappedFileCtx = this->Get(stModuleName);
		if (!lpMappedFileCtx)
		{
			APP_TRACE_LOG(LL_ERR, L"Target file: %s is not found in mapped file list!", stTempFileName.c_str());
			return false;
		}

		if (!CPEFunctions::IsValidPEHeader((HMODULE)lpMappedFileCtx->lpRawData))
		{
			APP_TRACE_LOG(LL_ERR, L"Target file: %s is not a valid PE file!", stTempFileName.c_str());
			return false;
		}
		
		return true;
	}

	void CSecureLoadLibrary::GetLoadedModuleList(std::vector <std::wstring>& vecModules)
	{
		for (const auto& ctxMappedFile : m_vMappedFiles)
		{
			vecModules.emplace_back(stdext::to_lower_wide(ctxMappedFile.wstName));
		}
	}
	HMODULE CSecureLoadLibrary::Find(const std::wstring& stName)
	{
		const auto stLowerName = stdext::to_lower_wide(stName);
		for (const auto& ctxMappedFile : m_vMappedFiles)
		{
			if (ctxMappedFile.wstOriginalName.find(stLowerName) != std::wstring::npos)
				return (HMODULE)ctxMappedFile.lpRawData;
		}
		return nullptr;
	}
	SMappedFileCtx* CSecureLoadLibrary::Get(const std::wstring& stName)
	{
		const auto stLowerName = stdext::to_lower_wide(stName);
		for (auto& ctxMappedFile : m_vMappedFiles)
		{
			if (ctxMappedFile.wstOriginalName.find(stLowerName) != std::wstring::npos)
				return &ctxMappedFile;
		}
		return nullptr;
	}

	bool CSecureLoadLibrary::Map(const std::wstring& stOriginalName, const std::wstring& stName, uint64_t offset, uint32_t size)
	{
		SMappedFileCtx ctx{ };
		ctx.bIsLoadedFromFile = true;
		ctx.wstOriginalName = stdext::to_lower_wide(stOriginalName);
		ctx.wstName = stName;

		auto hFile = g_winAPIs->CreateFileW(stName.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
		if (!IS_VALID_HANDLE(hFile))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileW(%s) failed with error: %u", stName.c_str(), g_winAPIs->GetLastError());
			return false;
		}

		auto hMapHandle = g_winAPIs->CreateFileMappingW(hFile, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr);
		if (!hMapHandle)
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileMapping(%s) failed with error: %u", stName.c_str(), g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		SYSTEM_INFO sys{};
		g_winAPIs->GetSystemInfo(&sys);

		offset -= offset % sys.dwAllocationGranularity;

//		ctx.lpMappedData = static_cast<uint8_t*>(g_winAPIs->MapViewOfFileEx(hMapHandle, FILE_MAP_READ, offset >> 32, offset & 0xffffffff, size, nullptr));
		ctx.lpMappedData = static_cast<uint8_t*>(g_winAPIs->MapViewOfFile(hMapHandle, FILE_MAP_READ, 0, 0, 0));
		if (!ctx.lpMappedData)
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileMapping(%s) failed with error: %u", stName.c_str(), g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hMapHandle);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}

		LARGE_INTEGER s{ 0 };
		if (!size && !g_winAPIs->GetFileSizeEx(hFile, &s))
		{
			APP_TRACE_LOG(LL_ERR, L"GetFileSize(%s) failed with error: %u", stName.c_str(), g_winAPIs->GetLastError());
			g_winAPIs->CloseHandle(hMapHandle);
			g_winAPIs->CloseHandle(hFile);
			return false;
		}
		if (!size)
			size = static_cast<uint32_t>(s.QuadPart);

		ctx.nMappedSize = size;

		ctx.lpRawData = ctx.lpMappedData + (offset % sys.dwAllocationGranularity);
		ctx.nRawSize = std::min<uint64_t>(size, s.QuadPart);

		// APP_TRACE_LOG(LL_SYS, L"%s, %llu, %u/%u", stName.c_str(), offset, size, (uint32_t)ctx.nRawSize);

		g_winAPIs->CloseHandle(hMapHandle);
		g_winAPIs->CloseHandle(hFile);

		if (ctx.lpRawData)
		{
			m_vMappedFiles.emplace_back(ctx);
			return true;
		}
		return false;
	}
}
