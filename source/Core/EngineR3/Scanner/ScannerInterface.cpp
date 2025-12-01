#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ScannerInterface.hpp"
#include "../IO/DataLoader.hpp"
#include "../../../Common/SimpleTimer.hpp"
#include "../../../Common/Keys.hpp"

#define CHECK_SMART_PTR(ptr)\
	if (!ptr || !ptr.get()) {\
		SCANNER_LOG(LL_CRI, L"%s could not allocated! Error: %u", #ptr, g_winAPIs->GetLastError());\
		return 0;\
	}


	
namespace NoMercy
{
	static std::atomic_bool gs_bScanCanRun = true;
	
	// -----------------------------------

	IScanner::IScanner()
	{
	}
	IScanner::~IScanner()
	{
	}

	DWORD IScanner::ThreadRoutine(void)
	{
		SCANNER_LOG(LL_SYS, L"Scanner thread event has been started!");

		const auto app = NoMercyCore::CApplication::Instance().DataInstance()->GetAppType();

		while (app == NM_CLIENT && !CApplication::Instance().NetworkIsReady())
		{
			g_winAPIs->Sleep(1000);
		}

//#ifdef __EXPERIMENTAL__
		// create parallel executor
		m_upTaskExecutor = stdext::make_unique_nothrow<tf::Executor>();

		// create a default observer
		auto observer = m_upTaskExecutor->make_observer<STFScannerObserver>(xorstr_(L"IScannerObserver"));

		// Allocate scan interfaces
		m_spProcessScanner = stdext::make_shared_nothrow<IProcessScanner>();
		CHECK_SMART_PTR(m_spProcessScanner);

		m_spWindowScanner = stdext::make_shared_nothrow<IWindowScanner>();
		CHECK_SMART_PTR(m_spWindowScanner);

		m_spServiceScanner = stdext::make_shared_nothrow<IServiceScanner>();
		CHECK_SMART_PTR(m_spServiceScanner);

		m_spDriverScanner = stdext::make_shared_nothrow<IDriverScanner>();
		CHECK_SMART_PTR(m_spDriverScanner);

		m_spHandleScanner = stdext::make_shared_nothrow<IHandleScanner>();
		CHECK_SMART_PTR(m_spHandleScanner);

		m_spFolderScanner = stdext::make_shared_nothrow<IFolderScanner>();
		CHECK_SMART_PTR(m_spFolderScanner);

		m_spObjectDirectoryScanner = stdext::make_shared_nothrow<IObjectDirectoryScanner>();
		CHECK_SMART_PTR(m_spObjectDirectoryScanner);

		m_spFileScanner = stdext::make_shared_nothrow<IFileScanner>();
		CHECK_SMART_PTR(m_spFileScanner);

		m_spModuleScanner = stdext::make_shared_nothrow<IModuleScanner>();
		CHECK_SMART_PTR(m_spModuleScanner);

		m_spSectionScanner = stdext::make_shared_nothrow<ISectionScanner>();
		CHECK_SMART_PTR(m_spSectionScanner);

		m_spThreadScanner = stdext::make_shared_nothrow<IThreadScanner>();
		CHECK_SMART_PTR(m_spThreadScanner);

		m_spHeapScanner = stdext::make_shared_nothrow<IHeapScanner>();
		CHECK_SMART_PTR(m_spHeapScanner);

		m_upYaraDetector = stdext::make_unique_nothrow<yaracpp::YaraDetector>();
		CHECK_SMART_PTR(m_upYaraDetector);

		// Wait for hook and watchers instance initializations
		if (app == NM_CLIENT)
		{
			auto timer = CStopWatch <std::chrono::milliseconds>();
			while (true)
			{
				if (timer.diff() > 100000)
				{
					SCANNER_LOG(LL_SYS, L"Scanner thread initilization has been timed out!");
					CApplication::Instance().OnCloseRequest(EXIT_ERR_SCANNER_INIT_TIMEOUT, 0);
					break;
				}

				if (!CApplication::Instance().FilterMgrInstance()->IsInitialized()) {
					SCANNER_LOG(LL_SYS, L"Waiting for Filter manager instance initilization...");
				}
				else if (!CApplication::Instance().WMIManagerInstance()->IsInitialized()) {
					SCANNER_LOG(LL_SYS, L"Waiting for WMI manager instance initilization...");
				}
				else if (!CApplication::Instance().WindowWatcherInstance()->IsInitialized()) {
					SCANNER_LOG(LL_SYS, L"Waiting for Window watcher instance initilization...");
				}
				else {
					break;
				}

				g_winAPIs->Sleep(1000);
			}
		}

		SCANNER_LOG(LL_SYS, L"Scanner base succesfully initialized! waiting for initilizations...");

		if (!stdext::is_debug_env())
			g_winAPIs->Sleep(60000); // sleep 1 min until everything is initialize

		SCANNER_LOG(LL_SYS, L"Scanner wait completed, scan instaces spawning!");

		// Main scanners
		m_spHandleScanner->ScanAll();

		// complete log
		SCANNER_LOG(LL_SYS, L"Main scans completed!");

		CheckWow32ReservedHook();
		CheckManualMappedModules();
		CheckGameWindows();

		// complete log
		SCANNER_LOG(LL_SYS, L"Client scans completed!");

#if 0
		// Create a taskflow
		tf::Taskflow tf_ft(xorstr_("tf_first_time_scanner"));

		// First time only
		tf_ft.emplace([&]() { CheckHiddenProcess(); }).name(xorstr_("hidden_proc"));
		tf_ft.emplace([&]() { CheckWow32ReservedHook(); }).name(xorstr_("wow32reserved"));
		tf_ft.emplace([&]() { CheckDevices(); }).name(xorstr_("devices"));
		tf_ft.emplace([&]() { CheckDnsHistory(); }).name(xorstr_("dns"));
		tf_ft.emplace([&]() { CheckVpn(); }).name(xorstr_("vpn"));
		tf_ft.emplace([&]() { CheckFirmwareTables(); }).name(xorstr_("firmware"));
		tf_ft.emplace([&]() { CheckProcessJobs(); }).name(xorstr_("proc jobs"));
		tf_ft.emplace([&]() { CheckLsassIntegrity(); }).name(xorstr_("lsass"));
		tf_ft.emplace([&]() { CheckTcpConnections(); }).name(xorstr_("tcp"));
		tf_ft.emplace([&]() { CheckUdpConnections(); }).name(xorstr_("udp"));
		tf_ft.emplace([&]() { CheckStackTrace(); }).name(xorstr_("stack"));
		tf_ft.emplace([&]() { CheckUsnJournal(); }).name(xorstr_("usn"));

		// run the taskflow
		m_upTaskExecutor->run(tf_ft).get();

		// complete log
		SCANNER_LOG(LL_SYS, L"First time scans completed!");

		// ----

		// Create a taskflow
		tf::Taskflow tf_main(xorstr_("tf_main_scanner"));

		// Main scanners
		tf_main.emplace([&]() { m_spWindowScanner->ScanAll(); }).name(xorstr_("window"));
		tf_main.emplace([&]() { m_spServiceScanner->ScanAll(); }).name(xorstr_("service"));
		tf_main.emplace([&]() { m_spDriverScanner->ScanAll(); }).name(xorstr_("driver"));
		tf_main.emplace([&]() { m_spHandleScanner->ScanAll(); }).name(xorstr_("handle"));
		tf_main.emplace([&]() { m_spObjectDirectoryScanner->ScanAll(); }).name(xorstr_("obj_dir"));

		// run the taskflow until gs_bScanCanRun is false
		m_upTaskExecutor->run(tf_main, [&]() { return !gs_bScanCanRun.load(); }).get();

		// run process scanner without parallel execution
		m_spProcessScanner->ScanAll();

		// complete log
		SCANNER_LOG(LL_SYS, L"Main scans completed!");

		// Create a taskflow
		tf::Taskflow tf_c(xorstr_("tf_client_scanner"));

		tf_c.emplace([&]() { CheckWow32ReservedHook(); }).name(xorstr_("wow32r"));
		tf_c.emplace([&]() { CheckManualMappedModules(); }).name(xorstr_("mmap"));
		tf_c.emplace([&]() { CheckVTableIntegrity(); }).name(xorstr_("vtable"));
		tf_c.emplace([&]() { CheckUnloadedModules(); }).name(xorstr_("unmod"));
		tf_c.emplace([&]() { CheckGameWindows(); }).name(xorstr_("gamewnd"));

		// run the taskflow until gs_bScanCanRun is false
		m_upTaskExecutor->run_until(tf_c, [&]() { return !gs_bScanCanRun.load(); }).get();

		// complete log
		SCANNER_LOG(LL_SYS, L"Client scans completed!");

		// remove the observer (optional)
		m_upTaskExecutor->remove_observer(std::move(observer));
#endif
//#endif

		// Use network instance as mutex, if connected to the server, it's probably mean the current instance is the main instance
		if (app == NM_CLIENT && CApplication::Instance().NetworkIsReady())
		{
			// Save scan cache periodically
			auto timer = CStopWatch <std::chrono::milliseconds>();
			while (true)
			{
				// if (timer.diff() > 5 * 60 * 1000)
				if (timer.diff() > 1 * 60 * 1000)
				{
					SCANNER_LOG(LL_TRACE, L"Saving scan cache...");
					const auto bRet = this->SaveScanCacheToFile();
					SCANNER_LOG(LL_SYS, L"Scan cache save completed with result: %d", bRet ? 1 : 0);

					timer.reset();
				}

				g_winAPIs->Sleep(3000);
			}
		}

		/*
		if (IS_VALID_SMART_PTR(CApplication::Instance().ThreadManagerInstance()))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(SELF_THREAD_SCANNER);
		}
		*/
		return 0;
	}

	DWORD WINAPI IScanner::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<IScanner*>(lpParam);
		return This->ThreadRoutine();
	}

	bool IScanner::InitializeScanner()
	{
		SCANNER_LOG(LL_SYS, L"Scanner initilization has been started!");

		if (!this->LoadScanCacheFromFile()) {
			SCANNER_LOG(LL_WARN, L"Scanner cache could not be loaded!");
		} else {
			SCANNER_LOG(LL_SYS, L"Scanner cache has been loaded!");
		}

		SCANNER_LOG(LL_SYS, L"Thread creation has been started");
		
		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_SCANNER, StartThreadRoutine, (void*)this, 0, true);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			SCANNER_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		SCANNER_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		return true;
	}
	void IScanner::FinalizeScanner()
	{
//		if (IS_VALID_SMART_PTR(m_upTaskExecutor))
//		{
			gs_bScanCanRun = false;
//		}
		
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_SCANNER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}

	
	bool IScanner::RunFirstTimeScans(uint8_t& pFailStep)
	{
		return CApplication::Instance().CheatDBManagerInstance()->ProcessPackedLocalCheatDB(CHEAT_DB_FILENAME, pFailStep);
	}

	
	void IScanner::SendViolationNotification(DWORD dwListIndex, const std::wstring& stID, bool bStreamed, std::wstring stMessage)
	{
		const auto wstKey = !stID.empty() ? stID : std::to_wstring(dwListIndex);
		if (stdext::in_vector(m_vSentViolationMessageIDs, wstKey))
		{
#ifdef _DEBUG
			SCANNER_LOG(LL_CRI, L"Already sent violation key: %s", wstKey.c_str());
#endif
			return;
		}
		m_vSentViolationMessageIDs.emplace_back(wstKey);

		SCANNER_LOG(LL_WARN, L"Violation notification send routine has been started! ID: %u(%s) Streamed: %d Message: %s",
			dwListIndex, stID.c_str(), bStreamed ? 1 : 0, stMessage.c_str()
		);

		stMessage = fmt::format(xorstr_(L"{0} :: {1} {2}"), stID, stMessage, bStreamed ? xorstr_(L"[remote_db]") : xorstr_(L"[local_db]"));

		CApplication::Instance().OnCheatDetect(CHEAT_VIOLATION_CDB, dwListIndex, stMessage);
	}

	
	bool IScanner::SaveScanCacheToFile()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxScanCacheMutex);

		static constexpr auto SCANNER_CACHE_EXPIRY_TIME = 60 * 60 * 24; // 1 day

		const auto stCurrentBootID = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetBootID();
		if (stCurrentBootID.empty())
		{
			SCANNER_LOG(LL_ERR, L"Current boot ID is empty!");
			return false;
		}

		const auto dwCurrentTime = stdext::get_current_epoch_time();
		if (!dwCurrentTime)
		{
			SCANNER_LOG(LL_ERR, L"Current time is invalid!");
			return false;
		}
		
		// Initialize rapidjson (pretty)writer
		GenericStringBuffer<UTF16<> > s;
		PrettyWriter <GenericStringBuffer<UTF16<>>, UTF16<> > writer(s);

		// Root object
		writer.StartObject();
		{
			// Write the boot ID
			writer.Key(xorstr_(L"boot_id"));
			writer.String(stCurrentBootID.c_str());

			// Write the expiry time
			writer.Key(xorstr_(L"expiry_time"));
			writer.Uint(dwCurrentTime + SCANNER_CACHE_EXPIRY_TIME);

			// Write the scan cache
			writer.Key(xorstr_(L"objects"));
			writer.StartObject();
			{
				for (const auto& [nID, vecItems] : m_mapScanCache)
				{
					const auto stID = std::to_wstring(nID);
					writer.Key(stID.c_str());

					writer.StartArray();
					{
						for (const auto& stItem : vecItems)
						{
							writer.String(stItem.c_str());
						}
					}
					writer.EndArray();
				}
			}
			// End of scan cache
			writer.EndObject();
		}
		// End root object
		writer.EndObject();

		// Create string output
		std::ostringstream oss;
		oss << std::setw(4) << s.GetString() << std::endl;
		const auto stSerialized = oss.str();

		// Check file already exist
		if (std::filesystem::exists(SCAN_CACHE_FILENAME))
		{
			SCANNER_LOG(LL_TRACE, L"Scan cache file already exist! File: %s", SCAN_CACHE_FILENAME);

			// Delete the old file
			std::error_code ec{};
			if (!std::filesystem::remove(SCAN_CACHE_FILENAME, ec) || ec)
			{
				SCANNER_LOG(LL_ERR, L"Can NOT delete old scan cache file! Error: %u", ec.value());
				return false;
			}

			SCANNER_LOG(LL_TRACE, L"Old scan cache file has been deleted!");
		}

		// Save to file
		msl::file_ptr out_file(SCAN_CACHE_FILENAME, xorstr_(L"wb"));
		if (!out_file)
		{
			SCANNER_LOG(LL_ERR, L"Scan cache file could not be created! Error: %u", errno);
			return false;
		}

		// Compress
		const auto bound = LZ4_compressBound(stSerialized.size());
		std::vector <uint8_t> compressed(bound);

		const auto compressedsize = LZ4_compress_HC(
			reinterpret_cast<const char*>(stSerialized.data()), reinterpret_cast<char*>(&compressed[0]),
			stSerialized.size(), bound, LZ4HC_CLEVEL_MAX
		);
		if (compressedsize >= bound || compressedsize == 0)
		{
			SCANNER_LOG(LL_ERR, L"Scan cache file could not be compressed! Raw: %u Comprossed: %u Capacity: %u", stSerialized.size(), compressedsize, bound);
			g_winAPIs->DeleteFileW(SCAN_CACHE_FILENAME);
			return false;
		}

		// Crypt
		std::vector <uint8_t> crypted(compressedsize);

		try
		{
			CryptoPP::CTR_Mode <CryptoPP::AES>::Encryption enc(&NoMercy::DefaultCryptionKey[0], 32, &NoMercy::DefaultCryptionKey[32]);
			enc.ProcessData(&crypted[0], reinterpret_cast<const uint8_t*>(compressed.data()), compressedsize);
		}
		catch (const CryptoPP::Exception& exception)
		{
			SCANNER_LOG(LL_ERR, L"Scan cache file could not be crypted! Error: %hs", exception.what());
			g_winAPIs->DeleteFileW(SCAN_CACHE_FILENAME);
			return false;
		}

		/// Write basic data
		// Magic
		const uint32_t magic = NM_CREATEMAGIC('N', 'M', 'C', 'F');
		out_file.write(&magic, sizeof(magic));

		// Version
		const uint32_t version = NOMERCY_FILE_CRYPT_VERSION;
		out_file.write(&version, sizeof(version));

		// Raw size
		const uint32_t in_size = stSerialized.size();
		out_file.write(&in_size, sizeof(in_size));

		// Raw hash
		const uint32_t in_raw_hash = XXH32(stSerialized.data(), in_size, 0);
		out_file.write(&in_raw_hash, sizeof(in_raw_hash));

		// Final size
		const uint32_t final_size = crypted.size();
		out_file.write(&final_size, sizeof(final_size));

		// Final hash
		const uint32_t final_hash = XXH32(crypted.data(), crypted.size(), 0);
		out_file.write(&final_hash, sizeof(final_hash));

		// Write final data
		out_file.write(crypted.data(), crypted.size());

		// Close output file
		out_file.close();

		SCANNER_LOG(LL_TRACE, L"Scan cache file saved!");
		return true;
	}

	bool IScanner::LoadScanCacheFromFile()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxScanCacheMutex);
		
		uint8_t pFailStep = 0;
		const auto stFileBuffer = CApplication::Instance().DataLoaderInstance()->LoadCryptedFile(SCAN_CACHE_FILENAME, pFailStep);
		if (stFileBuffer.empty())
		{
			SCANNER_LOG(LL_ERR, L"Scan cache file: %s could not load! Fail step: %u", SCAN_CACHE_FILENAME, pFailStep);
			return false;
		}

		auto document = rapidjson::GenericDocument<UTF16<>>{};
		document.Parse<kParseCommentsFlag>(stFileBuffer.c_str());
		if (document.HasParseError())
		{
			SCANNER_LOG(LL_ERR, L"Message: '%s' decode failed! Error: %hs offset: %u", stFileBuffer.c_str(), GetParseError_En(document.GetParseError()), document.GetErrorOffset());
			return false;
		}
		if (!document.IsObject())
		{
			SCANNER_LOG(LL_ERR, L"Message base is not an object! Type: %u", document.GetType());
			return false;
		}

		if (!document.HasMember(xorstr_(L"boot_id")))
		{
			SCANNER_LOG(LL_ERR, L"Message does not have a boot_id member!");
			return false;
		}
		else if (!document[xorstr_(L"boot_id")].IsString())
		{
			SCANNER_LOG(LL_ERR, L"boot_id is not a string! Type: %u", document[xorstr_(L"boot_id")].GetType());
			return false;
		}
		const auto stBootID = std::wstring(document[xorstr_(L"boot_id")].GetString(), document[xorstr_(L"boot_id")].GetStringLength());
		if (stBootID.empty())
		{
			SCANNER_LOG(LL_ERR, L"boot_id is empty!");
			return false;
		}

		const auto stCurrentBootID = NoMercyCore::CApplication::Instance().HWIDManagerInstance()->GetBootID();
		if (stCurrentBootID.empty())
		{
			SCANNER_LOG(LL_ERR, L"Current boot ID is empty!");
			return false;
		}
		
		if (stBootID != stCurrentBootID)
		{
			SCANNER_LOG(LL_WARN, L"Current boot ID: %s does not match with the boot ID in the cache: %s!", stCurrentBootID.c_str(), stBootID.c_str());
			g_winAPIs->DeleteFileW(SCAN_CACHE_FILENAME);
			return false;
		}
		
		if (!document.HasMember(xorstr_(L"expiry_time")))
		{
			SCANNER_LOG(LL_ERR, L"Message does not have a expiry_time member!");
			return false;
		}
		else if (!document[xorstr_(L"expiry_time")].IsNumber())
		{
			SCANNER_LOG(LL_ERR, L"expiry_time is not a number! Type: %u", document[xorstr_(L"expiry_time")].GetType());
			return false;
		}
		const auto dwExpiryTime = document[xorstr_(L"expiry_time")].GetUint();
		if (!dwExpiryTime)
		{
			SCANNER_LOG(LL_ERR, L"expiry_time is empty!");
			return false;
		}

		const auto dwCurrentTime = stdext::get_current_epoch_time();
		if (dwCurrentTime > dwExpiryTime)
		{
			SCANNER_LOG(LL_WARN, L"Current time: %u is greater than the expiry time: %u!", dwCurrentTime, dwExpiryTime);
			g_winAPIs->DeleteFileW(SCAN_CACHE_FILENAME);
			return false;
		}
		
		if (!document.HasMember(xorstr_(L"objects")))
		{
			SCANNER_LOG(LL_ERR, L"Message does not have a objects member!");
			return false;
		}
		else if (!document[xorstr_(L"objects")].IsObject())
		{
			SCANNER_LOG(LL_ERR, L"objects is not a object! Type: %u", document[xorstr_(L"objects")].GetType());
			return false;
		}
		if (document[xorstr_(L"objects")].ObjectEmpty())
		{
			SCANNER_LOG(LL_ERR, L"objects is empty!");
			return false;
		}
		
		auto bHasProcessedItem = false;
		const auto& pkObjCacheItems = document[xorstr_(L"objects")].GetObject();
		for (auto it = pkObjCacheItems.begin(); it != pkObjCacheItems.end(); ++it)
		{
			if (!it->name.IsString())
			{
				SCANNER_LOG(LL_ERR, L"Object key is not an string! Type: %u", it->name.GetType());
				continue;
			}
			const auto stKey = std::wstring(it->name.GetString(), it->name.GetStringLength());
			if (stKey.empty())
			{
				SCANNER_LOG(LL_ERR, L"Object key is empty!");
				continue;
			}
			SCANNER_LOG(LL_SYS, L"Object key: %s", stKey.c_str());

			if (!stdext::is_number(stKey))
			{
				SCANNER_LOG(LL_ERR, L"Object key is not a number!");
				continue;
			}

			if (!it->value.IsArray())
			{
				SCANNER_LOG(LL_ERR, L"Object value is not an array! Type: %u", it->value.GetType());
				continue;
			}

			const auto& pkArray = it->value.GetArray();
			if (pkArray.Empty())
			{
				SCANNER_LOG(LL_ERR, L"Object value array is empty!");
				continue;
			}

			std::vector <std::wstring> vecValues;

			// Iterate array
			for (const auto& pkValue : pkArray)
			{
				if (!pkValue.IsString())
				{
					SCANNER_LOG(LL_ERR, L"Array value is not a string! Type: %u", pkValue.GetType());
					continue;
				}

				const auto stValue = std::wstring(pkValue.GetString(), pkValue.GetStringLength());
				if (stValue.empty())
				{
					SCANNER_LOG(LL_ERR, L"Array value is empty!");
					continue;
				}
				SCANNER_LOG(LL_SYS, L"Array value: %s", stValue.c_str());

				vecValues.push_back(stValue);

				// Set flag
				bHasProcessedItem = true;
			}
			
			// Add to cache
			m_mapScanCache.emplace(stdext::str_to_u8(stKey), vecValues);

			// TODO: Load to class member for handle scan to fast check
		}
		
		return bHasProcessedItem;
	}

	bool IScanner::IsCachedScanObject(uint8_t nScanType, const std::wstring& stObjectName)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxScanCacheMutex);

		const auto it = m_mapScanCache.find(nScanType);
		if (it == m_mapScanCache.end())
			return false;
		
		const auto& vecScanCache = it->second;
		if (vecScanCache.empty())
			return false;

		return stdext::in_vector(vecScanCache, stObjectName);
	}

	bool IScanner::AddCachedScanObject(uint8_t nScanType, const std::wstring& stObjectName)
	{
		if (IsCachedScanObject(nScanType, stObjectName))
		{
			SCANNER_LOG(LL_WARN, L"Object: %s is already in the cache! Type: %u", stObjectName.c_str(), nScanType);
			return false;
		}
		
		std::lock_guard <std::recursive_mutex> __lock(m_mtxScanCacheMutex);

		auto itCache = m_mapScanCache.find(nScanType);
		if (itCache == m_mapScanCache.end())
		{
			m_mapScanCache.try_emplace(nScanType, std::vector <std::wstring >({ stObjectName }));
		}
		else
		{
			itCache->second.push_back(stObjectName);
		}
		
		return true;
	}

	uint32_t IScanner::GetCachedScannedObjectCount(uint8_t nScanType)
	{
		std::lock_guard <std::recursive_mutex> __lock(m_mtxScanCacheMutex);
		
		const auto it = m_mapScanCache.find(nScanType);
		if (it == m_mapScanCache.end())
		{
			SCANNER_LOG(LL_TRACE, L"Scan cache not found! Type: %u", nScanType);
			return 0;
		}

		const auto& vecCache = it->second;
		return vecCache.size();
	}
};
