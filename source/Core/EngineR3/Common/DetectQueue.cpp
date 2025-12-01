#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "DetectQueue.hpp"

namespace NoMercy
{
	CCheatQueue::CCheatQueue()
	{
	}
	CCheatQueue::~CCheatQueue()
	{
	}

	bool CCheatQueue::ProcessCheatQueueNode(std::shared_ptr <SCheatQueueCtx> spNode)
	{
		if (!spNode || !(spNode->id > CHEAT_VIOLATION_BASE && spNode->id < CHEAT_VIOLATION_MAX))
		{
			APP_TRACE_LOG(LL_ERR, L"Invalid cheat queue node, id: %d", spNode ? spNode->id : 0);
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Processing cheat queue node. ID: %u Sub: %u Error: %u Param: %s",
			spNode->id, spNode->sub_id, spNode->system_error, spNode->param.c_str()
		);

		const auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();
		if (ws && CApplication::Instance().NetworkIsReady())
		{
			std::vector <std::wstring> screenshots;
#if (MAX_SCREENSHOT_COUNT > 0)
			for (const auto& ss : spNode->screenshots)
			{
				if (!ss.empty())
					screenshots.push_back(ss);
			}
#endif

			ws->send_cheat_detection_message(spNode->ref_id, std::to_wstring(spNode->id), std::to_wstring(spNode->sub_id), spNode->param, screenshots);
		}
		else
		{
			stdext::json_data_container_t mapContainer;
			mapContainer.emplace(xorstr_(L"ref_id"), spNode->ref_id);
			mapContainer.emplace(xorstr_(L"id"), std::to_wstring(QUEUE_MESSAGE_TYPE_CHEAT_DETECT));
			mapContainer.emplace(xorstr_(L"cheat_id"), std::to_wstring(spNode->id));
			mapContainer.emplace(xorstr_(L"cheat_sub_id"), std::to_wstring(spNode->sub_id));
			mapContainer.emplace(xorstr_(L"cheat_details_msg"), spNode->param);
			mapContainer.emplace(xorstr_(L"system_error"), std::to_wstring(spNode->system_error));
			mapContainer.emplace(xorstr_(L"is_fatal"), std::to_wstring(spNode->fatal));

#if (MAX_SCREENSHOT_COUNT > 0)
			for (std::size_t i = 0; i < MAX_SCREENSHOT_COUNT; ++i)
			{
				if (!spNode->screenshots[i].empty())
					mapContainer.emplace(fmt::format(xorstr_(L"screenshot_{0}"), i), spNode->screenshots[i]);
			}
#endif
			
			CApplication::Instance().EnqueueWsMessage(stdext::dump_json(mapContainer));
		}
		
		return true;
	}

	bool CCheatQueue::ProcessCheatDetailsQueueNode(std::shared_ptr <SCheatDetailsQueueCtx> spNode)
	{
		if (!spNode)
			return false;



		return true;
	}

	void CCheatQueue::AppendCheatToQueue(std::shared_ptr <SCheatQueueCtx> spNode)
	{
		APP_TRACE_LOG(LL_WARN, L"Enqueued cheat db node. ID: %u Sub: %u Error: %u HasParam: %d", spNode->id, spNode->sub_id, spNode->system_error, !spNode->param.empty());

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
		m_kCheatQueue.enqueue(spNode);
	}
	std::shared_ptr <SCheatQueueCtx> CCheatQueue::DequeueCheatNode()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		std::shared_ptr <SCheatQueueCtx> node;
		m_kCheatQueue.try_dequeue(node);

		if (IS_VALID_SMART_PTR(node)) {
			APP_TRACE_LOG(LL_SYS, L"Dequeued cheat queue node: %p", node.get());
		}
		return node;
	}
	
	void CCheatQueue::AppendCheatDetailsToQueue(std::shared_ptr <SCheatDetailsQueueCtx> spNode)
	{
		APP_TRACE_LOG(LL_WARN, L"Enqueued cheat details db node. Ref: %s, File: %s, Process: %p", spNode->ref_id.c_str(), spNode->filename.c_str(), spNode->process);
	
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
		m_kCheatDetailsQueue.enqueue(spNode);
	}
	std::shared_ptr <SCheatDetailsQueueCtx> CCheatQueue::DequeueCheatDetailsNode()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		std::shared_ptr <SCheatDetailsQueueCtx> node;
		m_kCheatDetailsQueue.try_dequeue(node);

		if (IS_VALID_SMART_PTR(node)) {
			APP_TRACE_LOG(LL_SYS, L"Dequeued cheat details queue node: %p", node.get());
		}
		return node;
	}

	size_t CCheatQueue::GetDetailsTimerDiff()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		return m_kQueueDetailsTimer.diff();
	}
	void CCheatQueue::ResetDetailsTimer()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		m_kQueueDetailsTimer.reset();
	}

	DWORD CCheatQueue::QueueProcessor(void)
	{
		APP_TRACE_LOG(LL_TRACE, L"Cheat queue thread event has been started!");

		if (!CApplication::InstancePtr() || CApplication::Instance().AppIsFinalized())
			return 0;

		if (!CApplication::Instance().NetworkIsReady())
		{
			APP_TRACE_LOG(LL_WARN, L"Network instance is not yet ready!");
			g_winAPIs->Sleep(1000);
			return 0;
		}

		const auto ws = CApplication::Instance().NetworkMgrInstance()->GetWebSocketClient();
		if (!ws)
		{
			APP_TRACE_LOG(LL_WARN, L"Websocket client is not yet ready!");
			g_winAPIs->Sleep(1000);
			return 0;
		}

		const auto node1 = DequeueCheatNode();
		if (IS_VALID_SMART_PTR(node1))
		{
			if (!ProcessCheatQueueNode(node1))
			{
				APP_TRACE_LOG(LL_ERR, L"Cheat queue node: %u could not processed!", node1->id);
				CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_QUEUE_PROC_FAIL, 1);
				return 0;
			}
		}

		// Check details queuee after than 180 sec than last check
#ifndef _DEBUG
		if (GetDetailsTimerDiff() > 180)
#endif
		{
			// APP_TRACE_LOG(LL_SYS, L"Checking cheat queue details!");
			
			const auto node2 = DequeueCheatDetailsNode();
			if (IS_VALID_SMART_PTR(node2))
			{
				ResetDetailsTimer();
				
				if (!ProcessCheatDetailsQueueNode(node2))
				{
					APP_TRACE_LOG(LL_ERR, L"Cheat details queue node: %s could not processed!", node2->ref_id.c_str());
					CApplication::Instance().OnCloseRequest(EXIT_ERR_CHEAT_QUEUE_PROC_FAIL, 2);
					return 0;
				}
			}
		}

		return 0;
	}

	DWORD WINAPI CCheatQueue::StartThreadRoutine(LPVOID lpParam)
	{
		const auto This = reinterpret_cast<CCheatQueue*>(lpParam);
		return This->QueueProcessor();
	}

	bool CCheatQueue::InitializeThread()
	{
		APP_TRACE_LOG(LL_SYS, L"Thread creation has been started!");

		const auto thread = CApplication::Instance().ThreadManagerInstance()->CreateCustomThread(SELF_THREAD_CHEAT_QUEUE, StartThreadRoutine, (void*)this, 2000, false);
		if (!IS_VALID_SMART_PTR(thread) || thread->IsValid() == false)
		{
			APP_TRACE_LOG(LL_ERR, L"Thread can NOT created! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		APP_TRACE_LOG(LL_SYS, L"Info - %u[%p->%p][%d-%s] - Completed! Thread:%p",
			thread->GetID(), thread->GetHandle(), thread->GetStartAddress(), thread->GetCustomCode(), thread->GetThreadCustomName().c_str(), thread.get()
		);

		ResetDetailsTimer();
		return true;
	}
	void CCheatQueue::ReleaseThread()
	{
		const auto currentThread = CApplication::Instance().ThreadManagerInstance()->GetThreadFromThreadCode(SELF_THREAD_CHEAT_QUEUE);
		if (IS_VALID_SMART_PTR(currentThread))
		{
			CApplication::Instance().ThreadManagerInstance()->DestroyThread(currentThread);
		}
	}
};
