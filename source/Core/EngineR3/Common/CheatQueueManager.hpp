#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

namespace NoMercy
{
	class CCheatQueueManager : public std::enable_shared_from_this <CCheatQueueManager>
	{
	public:
		CCheatQueueManager();
		virtual ~CCheatQueueManager();

		bool InitializeThread();
		void ReleaseThread();

		void AppendCheatToQueue(std::shared_ptr <SCheatDBNode> spNode);
		void AppendToolToQueue(std::shared_ptr <SBlockedToolNode> spNode);

	protected:
		bool ProcessCheatDBNode(std::shared_ptr <SCheatDBNode> spNode);
		std::shared_ptr <SCheatDBNode> DequeueCheatNode();

		bool ProcessBlockedToolNode(std::shared_ptr <SBlockedToolNode> spNode);
		std::shared_ptr <SBlockedToolNode> DequeueToolNode();

		DWORD					QueueProcessor(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		moodycamel::ConcurrentQueue <std::shared_ptr <SBlockedToolNode>>	m_kBlockedToolQueue;
		moodycamel::ConcurrentQueue <std::shared_ptr <SCheatDBNode>>		m_kCheatQueue;
		std::vector <std::shared_ptr <SCheatDBNode>>						m_vCheatNodes;

		// TODO
		std::shared_ptr <IQuarentineNode <SWindowCheckObjects>> m_spWindowObjects;
	};
};
