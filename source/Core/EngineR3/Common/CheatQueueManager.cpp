#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "CheatQueueManager.hpp"

namespace NoMercy
{
	CCheatQueueManager::CCheatQueueManager()
	{
	}
	CCheatQueueManager::~CCheatQueueManager()
	{
	}

	bool CCheatQueueManager::ProcessCheatDBNode(std::shared_ptr <SCheatDBNode> spNode)
	{
		if (!spNode || spNode->type == CHEAT_DB_SCAN_NULL || spNode->type >= CHEAT_DB_SCAN_MAX)
			return false;

		APP_TRACE_LOG(LL_SYS, L"Processing cheat db node. Index: %u(%s) Scan Type: %u Param count: %u", spNode->idx, spNode->id.c_str(), spNode->type, spNode->params.size());

		switch (spNode->type)
		{
			case CHEAT_DB_SCAN_PROCESS_NAME:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByName(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_PROCESS_CHECKSUM:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsProcessExistByChecksum(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_MODULE_NAME:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsModuleExistByNameInGameProcesses(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_MODULE_FILE_CHECKSUM:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsModuleExistByChecksum(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_WINDOW_TITLE_CLASS:
			{
				if (spNode->params.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsWindowsExistByTitleClass(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0), stdext::get_map_value_by_index(spNode->params, 1)
				);
				return true;
			};
			case CHEAT_DB_SCAN_WINDOW_STYLE_EXSTYLE:
			{
				if (spNode->params.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsWindowsExistByStyleExstyle(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0), stdext::get_map_value_by_index(spNode->params, 1)
				);
				return true;
			};
			case CHEAT_DB_SCAN_FILE_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsFileExistByName(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_FILE_CHECKSUM:
			{
				if (spNode->params.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_CheckFileSum(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2)
				);
				return true;
			};
			case CHEAT_DB_SCAN_REGION_ADDR_SUM:
			{
				if (spNode->params.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsRegionExistInGameProcesses(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2)
				);
				return true;
			};
			case CHEAT_DB_SCAN_PATTERN_SEARCH:
			{
				if (spNode->params.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsPatternExistInGameProcesses(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2)
				);
				return true;
			};
			case CHEAT_DB_SCAN_PATTERN_SEARCH_GLOBAL:
			{
				if (spNode->params.size() != 3)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsPatternExistInAllProcesses(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2),
					0
				);
				return true;
			};
			case CHEAT_DB_SCAN_MEM_DUMP_SEARCH:
			{
				if (spNode->params.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsMemDumpExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0), stdext::get_map_value_by_index(spNode->params, 1)
				);
				return true;
			};
			case CHEAT_DB_SCAN_FILE_MAPPING_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsFileMappingExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			}
			case CHEAT_DB_SCAN_MUTEX_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsMutexExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_EVENT_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsEventExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_SEMAPHORE_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsSemaphoreExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_JOB_OBJECT_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsJobObjectExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_SYMLINK_EXIST:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsSymLinkExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_API_MODULE_BOUND:
			{
				if (spNode->params.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_CheckAPIModuleBound(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0), stdext::get_map_value_by_index(spNode->params, 1)
				);
				return true;
			};
			case CHEAT_DB_SCAN_MEM_CHECKSUM:
			{
				if (spNode->params.size() != 4)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsMemChecksumCorrupted(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2),
					stdext::get_map_value_by_index(spNode->params, 3)
				);
				return true;
			};
			case CHEAT_DB_SCAN_MEM_EXTENDED_CHECKSUM:
			{
				if (spNode->params.size() != 5)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsMemCorrupted(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2),
					stdext::get_map_value_by_index(spNode->params, 3),
					stdext::get_map_value_by_index(spNode->params, 4)
				);
				return true;
			};
			case CHEAT_DB_SCAN_THREAD_EBP_REGISTER:
			{
				if (spNode->params.size() != 4)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsEbpContextCorrupted(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0),
					stdext::get_map_value_by_index(spNode->params, 1),
					stdext::get_map_value_by_index(spNode->params, 2),
					stdext::get_map_value_by_index(spNode->params, 3)
				);
				return true;
			};
			case CHEAT_DB_SCAN_YARA_FILE:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}

				const auto wstContent = stdext::get_map_value_by_index(spNode->params, 0);
				CApplication::Instance().ScannerInstance()->CDB_CheckYaraFile(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::string_to_byte_array(wstContent)
				);
				return true;
			};
			case CHEAT_DB_SCAN_REGISTRY_KEY:
			{
				if (spNode->params.size() != 2)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_CheckRegistryKeyExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false },
					stdext::get_map_value_by_index(spNode->params, 0), stdext::get_map_value_by_index(spNode->params, 1)
				);
				return true;
			};
			case CHEAT_DB_SCAN_WINDOWS_STATION:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsWindowsStationExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_WAITABLE_TIMER:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsWaitableTimerExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			case CHEAT_DB_SCAN_HANDLE_OBJECT_NAME:
			{
				if (spNode->params.size() != 1)
				{
					APP_TRACE_LOG(LL_ERR, L"Processing cheat db node failed. Param count: %u is not correct. Scan Type: %u", spNode->params.size(), spNode->type);
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_PROCESS_INCORRECT_PARAM_COUNT, spNode->type);
					return false;
				}
				CApplication::Instance().ScannerInstance()->CDB_IsHandleObjectExist(
					{ spNode->idx, spNode->id, !spNode->from_local_db, false }, stdext::get_map_value_by_index(spNode->params, 0)
				);
				return true;
			};
			default:
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown scan type: %u", spNode->type);
				CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_DB_NOT_IMPLEMENTED_SCAN_TYPE, spNode->type);
				return false;
			}
		}
	}

	void CCheatQueueManager::AppendCheatToQueue(std::shared_ptr <SCheatDBNode> spNode)
	{
		APP_TRACE_LOG(LL_SYS, L"Enqueued cheat db node. Index: %u(%s) Scan Type: %u Param count: %u", spNode->idx, spNode->id.c_str(), spNode->type, spNode->params.size());
		m_vCheatNodes.emplace_back(spNode); // Store in memory for check later in runtime scanner methods
		m_kCheatQueue.enqueue(spNode);
	}
	std::shared_ptr <SCheatDBNode> CCheatQueueManager::DequeueCheatNode()
	{
		std::shared_ptr <SCheatDBNode> node;
		m_kCheatQueue.try_dequeue(node);

		if (IS_VALID_SMART_PTR(node)) {
			APP_TRACE_LOG(LL_SYS, L"Dequeued cheat db node: %p", node.get());
		}
		return node;
	}

	DWORD CCheatQueueManager::QueueProcessor(void)
	{
		static auto s_bOnce = false;
		if (!s_bOnce)
		{
			s_bOnce = true;
			APP_TRACE_LOG(LL_WARN, L"Cheat queue manager thread event has been started!");
		}

		if (!CApplication::InstancePtr())
			return 0;

//#ifndef _DEBUG
		if (!CApplication::Instance().NetworkIsReady())
			return 0;

		const auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();
		if (!ws)
			return 0;
#//endif

		if (m_kBlockedToolQueue.size_approx() || m_kCheatQueue.size_approx())
		{
			APP_TRACE_LOG(LL_WARN, L"Current queue object counts: %u/%u", m_kBlockedToolQueue.size_approx(), m_kCheatQueue.size_approx());
		}

		auto spToolNode = DequeueToolNode();
		if (IS_VALID_SMART_PTR(spToolNode))
		{
			try
			{
				ProcessBlockedToolNode(spToolNode);
			}
			catch (const std::bad_alloc& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for section context. Exception: %hs", e.what());
			}
			catch (const std::exception& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Processing blocked tool node failed. Exception: %hs", e.what());
			}
			catch (...)
			{
				APP_TRACE_LOG(LL_CRI, L"Processing blocked tool node failed. Unknown exception!");
			}
		}

		auto spCheatNode = DequeueCheatNode();
		if (IS_VALID_SMART_PTR(spCheatNode))
		{
			try
			{
				ProcessCheatDBNode(spCheatNode);
			}
			catch (const std::bad_alloc& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Failed to allocate memory for section context. Exception: %hs", e.what());
			}
			catch (const std::exception& e)
			{
				APP_TRACE_LOG(LL_CRI, L"Processing cheat db node failed. Exception: %hs", e.what());
			}
			catch (...)
			{
				APP_TRACE_LOG(LL_CRI, L"Processing cheat db node failed. Unknown exception!");
			}
		}

		return 0;
	}

	DWORD WINAPI CCheatQueueManager::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CCheatQueueManager*>(lpParam);
		return This->QueueProcessor();
	}

	bool CCheatQueueManager::InitializeThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(
			SELF_THREAD_CHEAT_QUEUE_MANAGER,
			StartThreadRoutine,
			(void*)this,
#ifdef _DEBUG
			300,
#else
			2500,
#endif
			false
		);
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
	void CCheatQueueManager::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_CHEAT_QUEUE_MANAGER);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
