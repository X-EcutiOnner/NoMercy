#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <cstdint>
#include <thread>
#include <atomic>

class CLock
{
	public:
		virtual ~CLock() {}

		virtual void Lock() = 0;
		virtual bool TryLock() = 0;
		virtual void Unlock() = 0;
};

class CCSLock : public CLock
{
	public:
		CCSLock(uint32_t uSpinCount = 0)
		{
			if (uSpinCount)
				InitializeCriticalSectionAndSpinCount(&m_cs, uSpinCount);
			else
				InitializeCriticalSection(&m_cs);
		}
		~CCSLock()				{ DeleteCriticalSection(&m_cs);			}

		virtual void Lock()		{ EnterCriticalSection(&m_cs);			}
		virtual bool TryLock()	{ return TryEnterCriticalSection(&m_cs);}
		virtual void Unlock()	{ LeaveCriticalSection(&m_cs);			}

	private:
		CRITICAL_SECTION m_cs;
};

class CScopedLock
{
	public:
		CScopedLock()
		{
			CCSLock lock{};
			m_pLockPtr = &lock;
			
			m_pLockPtr->Lock();
		}
		CScopedLock(CLock & lock) :
			m_pLockPtr(&lock)
		{
			m_pLockPtr->Lock();
		}

		~CScopedLock()
		{
			m_pLockPtr->Unlock();
		}

	private:
		CLock * m_pLockPtr;
};

class CAtomicLock
{
public:
	CAtomicLock() = default;
	~CAtomicLock() = default;

	void Lock()
	{
		while (m_lock.test_and_set())
		{
			std::this_thread::yield();
		}
	}

	void Unlock()
	{
		m_lock.clear();
	}

private:
	std::atomic_flag m_lock{ };
};

class CRWLock
{
public:
	CRWLock() :
		m_srwLock(SRWLOCK_INIT)
	{
	}
	~CRWLock() = default;

	inline void LockShared() { AcquireSRWLockShared(&m_srwLock); }
	inline void UnlockShared() { ReleaseSRWLockShared(&m_srwLock); }

	inline void LockExclusive() { AcquireSRWLockExclusive(&m_srwLock); }
	inline void UnlockExclusive() { ReleaseSRWLockExclusive(&m_srwLock); }

	inline bool TryLockShared() { return TryAcquireSRWLockShared(&m_srwLock); }
	inline bool TryLockExclusive() { return TryAcquireSRWLockExclusive(&m_srwLock); }

private:
	SRWLOCK m_srwLock;
};
