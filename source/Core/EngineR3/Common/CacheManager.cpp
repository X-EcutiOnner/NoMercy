#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "CacheManager.hpp"
#include "../../EngineR3_Core/include/ProcessFunctions.hpp"
#include "../../EngineR3_Core/include/ProcessEnumerator.hpp"
#include "../../EngineR3_Core/include/PEHelper.hpp"

namespace NoMercy
{
	CCacheManager::CCacheManager() :
		m_pvFSRedirectionCache(nullptr)
	{
	}
	CCacheManager::~CCacheManager()
	{
	}

	std::wstring CCacheManager::GetCachedValue(const std::wstring& wstKey) const
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmLock);
		
		const auto it = m_mapCache.find(wstKey);
		if (it == m_mapCache.end())
			return {};

		return it->second;
	}
	void CCacheManager::RegisterCacheValue(const std::wstring& wstKey, const std::wstring& wstValue)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmLock);

		const auto it = m_mapCache.find(wstKey);
		if (it != m_mapCache.end())
			return;

		m_mapCache[wstKey] = wstValue;
	}
	void CCacheManager::DeleteCachedValue(const std::wstring& wstKey)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmLock);

		auto it = m_mapCache.find(wstKey);
		if (it == m_mapCache.end())
			return;

		m_mapCache.erase(it);
	}

	std::wstring CCacheManager::GetCacheRequestTypeStr(const ECacheRequestTypes& type) const
	{
		switch (type)
		{
			case ECacheRequestTypes::SHA1:
				return xorstr_(L"SHA1");
			case ECacheRequestTypes::SHA256_REGION:
				return xorstr_(L"SHA256_REGION");
			default:
				return {};
		}
	}
	std::wstring CCacheManager::GetCachedFileSHA1(const std::wstring& wstFilename) const
	{
		const auto wstLowerFilename = stdext::to_lower_wide(wstFilename);
		const auto wstFilenameHash = stdext::hash(wstLowerFilename.c_str());
		const auto wstCacheKey = fmt::format(xorstr_(L"{0}_{1}"), GetCacheRequestTypeStr(ECacheRequestTypes::SHA1), wstFilenameHash);
		return this->GetCachedValue(wstCacheKey);
	}
	std::wstring CCacheManager::GetCachedRegionSHA256(DWORD dwProcessID, uint64_t pMemBase) const
	{
		const auto wstCacheKey = fmt::format(xorstr_(L"{0}_{1}_{2}"),
			GetCacheRequestTypeStr(ECacheRequestTypes::SHA256_REGION), dwProcessID, fmt::ptr((ptr_t)pMemBase)
		);
		return this->GetCachedValue(wstCacheKey);
	}

	void CCacheManager::__CacheRunningProcessSHA1Hashes()
	{
		auto spProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(spProcEnumerator))
		{
			auto vProcs = spProcEnumerator->EnumerateProcesses();
			for (auto& hProc : vProcs)
			{
				if (IS_VALID_HANDLE(hProc))
				{
					const auto wstProcName = CProcessFunctions::GetProcessName(hProc);
					if (!wstProcName.empty())
					{
						this->AppendToRequestQueue(std::make_tuple(ECacheRequestTypes::SHA1, wstProcName));
					}
				}

				g_winAPIs->Sleep(10);
			}
			spProcEnumerator.reset();
		}

		return;
	}
	void CCacheManager::__CacheRunningProcessRegionSHA256Hashes()
	{
		auto upProcEnumerator = stdext::make_unique_nothrow<CProcessEnumerator>(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION);
		if (IS_VALID_SMART_PTR(upProcEnumerator))
		{
			for (auto hProcess : upProcEnumerator->EnumerateProcesses())
			{
				if (IS_VALID_HANDLE(hProcess))
				{
					if (NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->IsValidHandle(hProcess))
					{
						const auto dwProcessID = g_winAPIs->GetProcessId(hProcess);

						CApplication::Instance().ScannerInstance()->EnumerateSections(hProcess, false, [&](std::shared_ptr <SSectionEnumContext> pCurrSection) {
							const auto mask = (PAGE_READONLY | PAGE_READWRITE | /* PAGE_WRITECOPY | */ PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
							if (pCurrSection->Protect & mask)
							{
								const auto wstCacheKey = fmt::format(xorstr_(L"{0}_{1}_{2}"),
									GetCacheRequestTypeStr(ECacheRequestTypes::SHA256_REGION), dwProcessID, fmt::ptr(pCurrSection->BaseAddress)
								);
								this->AppendToRequestQueue(std::make_tuple(ECacheRequestTypes::SHA256_REGION, wstCacheKey));
							}
						});
					}
				}
			}
			upProcEnumerator.reset();
		}

		return;
	}

	bool CCacheManager::IsAlreadyCachedRequest(TCacheRequestBuffer kNode) const
	{
		const auto kScanType = std::get<0>(kNode);
		const auto wstBuffer = std::get<1>(kNode);
		const auto wstSerialized = fmt::format(xorstr_(L"{0}_{1}"), GetCacheRequestTypeStr(kScanType), wstBuffer);

		return !this->GetCachedValue(wstSerialized).empty();
	}
	void CCacheManager::AppendToRequestQueue(TCacheRequestBuffer kNode)
	{
		if (IsAlreadyCachedRequest(kNode))
			return;

		auto spNode = std::make_shared<TCacheRequestBuffer>(kNode);
		m_kCacheRequests.enqueue(spNode);
	}
	bool CCacheManager::ProcessRequestNode(std::shared_ptr <TCacheRequestBuffer> spNode)
	{
		if (!CApplication::Instance().AppIsInitiliazed())
			return false;
		if (!IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
			return false;
		if (!CApplication::Instance().AppIsInitializedThreadCompleted())
			return false;

		if (IS_VALID_SMART_PTR(spNode))
		{
			if (IsAlreadyCachedRequest(*spNode.get()))
				return true;

			const auto kScanType = std::get<0>(*spNode.get());
			switch (kScanType)
			{
				case ECacheRequestTypes::SHA1:
				{
					auto wstFilename = std::get<1>(*spNode.get());
					if (wstFilename.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"Cache request value is empty!");
						return false;
					}

					if (stdext::in_vector(m_vecSkippedFile, wstFilename))
						return true;

					/*
					PVOID OldValue = nullptr;
					if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &OldValue))
					{
						APP_TRACE_LOG(LL_ERR, L"FS redirection enable failed with error: %u", g_winAPIs->GetLastError());
						return false;
					}
					*/

					if (!NoMercyCore::CApplication::Instance().DirFunctionsInstance()->IsFileExist(wstFilename))
					{
						APP_TRACE_LOG(LL_WARN, L"File: %s does not exist!", wstFilename.c_str());
						m_vecSkippedFile.emplace_back(wstFilename);
						// NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
						return false;
					}
					const auto wstFileHash = NoMercyCore::CApplication::Instance().CryptFunctionsInstance()->GetFileSHA1(wstFilename);
					if (wstFileHash.empty())
					{
						APP_TRACE_LOG(LL_ERR, L"File hash could not created for: %s", wstFilename.c_str());
						m_vecSkippedFile.emplace_back(wstFilename);
						// NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);
						return false;
					}

					// NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, OldValue, nullptr);

					wstFilename = stdext::to_lower_wide(wstFilename);
					const auto wstFilenameHash = stdext::hash(wstFilename.c_str());
					const auto wstCacheKey = fmt::format(xorstr_(L"{0}_{1}"), GetCacheRequestTypeStr(ECacheRequestTypes::SHA1), wstFilenameHash);

					this->RegisterCacheValue(wstCacheKey, wstFileHash);
					return true;
				} break;

				case ECacheRequestTypes::SHA256_REGION:
				{
					/*
					const auto wstCacheKey = fmt::format(xorstr_(L"{0}_{1}_{2}"),
						GetCacheRequestTypeStr(ECacheRequestTypes::SHA256_REGION), dwProcessID, fmt::ptr(pCurrSection->BaseAddress)
					);
					*/
					__nop();
				} break;

				default:
				{
					APP_TRACE_LOG(LL_ERR, L"Unknown cache request type: %u", (uint32_t)kScanType);
					return false;
				}
			}
		}

		return false;
	}
	std::shared_ptr <TCacheRequestBuffer> CCacheManager::DequeueRequestCacheNode()
	{
		std::shared_ptr <TCacheRequestBuffer> node;
		m_kCacheRequests.try_dequeue(node);

		return node;
	}

	DWORD CCacheManager::CacheManagerThreadProcessor(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Cache manager event has been started!");

		if (!NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(true, nullptr, &m_pvFSRedirectionCache))
		{
			APP_TRACE_LOG(LL_ERR, L"FS redirection enable failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		// Bulk cache requests
		__CacheRunningProcessSHA1Hashes();
	//	__CacheRunningProcessRegionSHA256Hashes(); // TODO

		while (true)
		{
			if (m_abReleaseStarted.load())
				continue;

			auto spCacheNode = DequeueRequestCacheNode();
			if (IS_VALID_SMART_PTR(spCacheNode))
			{
				try
				{
					ProcessRequestNode(spCacheNode);
				}
				catch (const std::bad_alloc& e)
				{
					APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for section context. Exception: %hs", e.what());
				}
				catch (const std::exception& e)
				{
					APP_TRACE_LOG(LL_CRI, L"Processing node failed. Exception: %hs", e.what());
				}
				catch (...)
				{
					auto wstFilename = std::get<1>(*spCacheNode.get());
					APP_TRACE_LOG(LL_CRI, L"Processing node failed. Unknown exception! Node: '%s'", wstFilename.c_str());
				}
			}

			g_winAPIs->Sleep(100);
		}

		NoMercyCore::CApplication::Instance().WinAPIManagerInstance()->NTHelper()->ManageFsRedirection(false, m_pvFSRedirectionCache, nullptr);
		return 0;
	}

	DWORD WINAPI CCacheManager::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CCacheManager*>(lpParam);
		return This->CacheManagerThreadProcessor();
	}

	bool CCacheManager::InitializeThread() const
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_CACHE_MANAGER, StartThreadRoutine, (void*)this, 0, true);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
	void CCacheManager::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_CACHE_MANAGER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			m_abReleaseStarted.store(true);
			g_winAPIs->Sleep(1500);

			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}

	bool CCacheManager::SaveCachesToDBFile(const std::wstring& wstFilename) const
	{
		// TODO
		return true;
	}
	bool CCacheManager::LoadSavedCachesFromDBFile(const std::wstring& wstFilename) const
	{
		// TODO
		return true;
	}
};
