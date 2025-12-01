#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <mutex>
#include <deque>

template <typename T>
class CQueue
{
	using TCustomCallback = std::function<void(T)>;

	public:
		CQueue() : m_pCallback(nullptr), m_pTimerID(nullptr) { }
		~CQueue() = default;

		void BindCallback(TCustomCallback pFunc)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);
			
			m_pCallback = pFunc;
		}

		size_t GetWorkObjectsSize()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			return m_kWorkList.size();
		}

		bool HasWorkObject()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			return (m_kWorkList.size() > 0);
		}

		template <class cData>
		bool InsertObject(cData data)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			// If already queue'd object, dont add duplicate
			if (m_kWorkList.size() > 0 && std::find(m_kWorkList.begin(), m_kWorkList.end(), data) != m_kWorkList.end())
				return false;

			if (m_kCheckedList.size() > 0 && std::find(m_kCheckedList.begin(), m_kCheckedList.end(), data) != m_kCheckedList.end())
				return false;

			// Add to queue
			m_kWorkList.push_back(data);
			return true;
		}

		bool ProcessFirstObject()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

#ifdef _DEBUG
			if (!m_pCallback)
			{
				assert(!"Null callback ptr!!!");
				return false;
			}
#endif

			if (!m_kWorkList.empty())
			{
				m_pCallback(m_kWorkList.front());
				m_kCheckedList.push_back(m_kWorkList.front());
				m_kWorkList.pop_front();
				return true;
			}

			return false;
		}

		T & GetFirstObject()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			return m_kWorkList.front();
		}

		void RemoveFirstObject()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			m_kCheckedList.push_back(m_kWorkList.front());
			m_kWorkList.pop_front();
		}

		template <class cData>
		bool HasListed(cData data)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			if (m_kWorkList.size() > 0 && std::find(m_kWorkList.begin(), m_kWorkList.end(), data) != m_kWorkList.end())
				return true;

			return false;
		}

		template <class cData>
		bool HasProcessed(cData data)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			if (m_kCheckedList.size() > 0 && std::find(m_kCheckedList.begin(), m_kCheckedList.end(), data) != m_kCheckedList.end())
				return true;

			return false;
		}

		void StartWorker(uint32_t interval)
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			// TODO: SetTimer with given internal, run ProcessFirstObject in tick, lambda interface
		}

		void EndWorker()
		{
			std::lock_guard <std::recursive_mutex> __lock(m_Mutex);

			// TODO: KillTimer
		}

	private:
		mutable std::recursive_mutex m_Mutex;

		std::deque <T> m_kWorkList;
		std::deque <T> m_kCheckedList;

		TCustomCallback m_pCallback;

		uintptr_t m_pTimerID;
};
