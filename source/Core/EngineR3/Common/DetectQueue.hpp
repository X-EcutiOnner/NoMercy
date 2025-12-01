#pragma once
#include <memory>
#include <vector>
#include <functional>
#include "../CheatIDs.hpp"

namespace NoMercy
{
	struct SCheatQueueCtx
	{
		std::wstring	ref_id{ L"" };
		uint32_t		id{ 0 };
		uint32_t		sub_id{ 0 };
		uint32_t		system_error{ 0 };
		bool			fatal{ false };
		std::wstring	param{ L"" };
#if (MAX_SCREENSHOT_COUNT > 0)
		std::wstring	screenshots[MAX_SCREENSHOT_COUNT];
#endif
	};
	struct SCheatDetailsQueueCtx
	{
		std::wstring	ref_id{ L"" };
		HANDLE			process{ nullptr };
		std::wstring	filename{ L"" };
	};
	
	class CCheatQueue : public std::enable_shared_from_this <CCheatQueue>
	{
	public:
		CCheatQueue();
		virtual ~CCheatQueue();

		bool InitializeThread();
		void ReleaseThread();

		void AppendCheatToQueue(std::shared_ptr <SCheatQueueCtx> spNode);
		void AppendCheatDetailsToQueue(std::shared_ptr <SCheatDetailsQueueCtx> spNode);

		size_t GetDetailsTimerDiff();
		void ResetDetailsTimer();

	protected:
		bool ProcessCheatQueueNode(std::shared_ptr <SCheatQueueCtx> spNode);
		bool ProcessCheatDetailsQueueNode(std::shared_ptr <SCheatDetailsQueueCtx> spNode);
		
		std::shared_ptr <SCheatQueueCtx> DequeueCheatNode();
		std::shared_ptr <SCheatDetailsQueueCtx> DequeueCheatDetailsNode();

		DWORD					QueueProcessor(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		mutable std::recursive_mutex m_rmMutex;

		moodycamel::ConcurrentQueue <std::shared_ptr <SCheatQueueCtx>> m_kCheatQueue;
		moodycamel::ConcurrentQueue <std::shared_ptr <SCheatDetailsQueueCtx>> m_kCheatDetailsQueue;
		CStopWatch <std::chrono::seconds> m_kQueueDetailsTimer;
	};
};