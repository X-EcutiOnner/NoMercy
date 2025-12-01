#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace NoMercy
{
	enum class EHWBPType
	{
		execute		= 0x0,
		write		= 0x1,
		readwrite	= 0x3
	};

	enum class EHWBPSize
	{
		one		= 0x0,
		two		= 0x1,
		four	= 0x3,
		eight	= 0x2
	};

	class CProcess;

	class CThread
	{
		public:
			CThread() = default;
			CThread(const DWORD dwThreadId, const DWORD dwAccessMask = THREAD_ALL_ACCESS, CProcess* Process = nullptr);
			CThread(const HANDLE hThread, CProcess* Process = nullptr);
			~CThread();

			// moveable
			CThread(CThread&& other) noexcept;
			CThread& operator=(CThread&& other) noexcept;

			explicit operator bool() noexcept;

			void		Terminate();
			void		ClearDebugRegisters();
			void		Join(const DWORD dwMSDelay);
			void		SetPriority(const int iPriority);
			bool		PutHWBP(const void* address, const bool enable, const EHWBPType type, const EHWBPSize size);

			HANDLE		GetHandle();
			DWORD		GetID();
			DWORD		GetCustomCode();
			std::wstring	GetThreadCustomName();
			PVOID		GetStartAddress();
			int			GetPriority();
			DWORD		GetProcessID();
			std::shared_ptr <CONTEXT>	GetContext();
			PVOID		GetModuleBaseAddress();
			std::size_t	GetModuleSize();
			ptr_t		GetThreadTEB();

			std::wstring GetThreadOwnerFullName();
			std::wstring GetThreadOwnerFileName();

			bool		IsValid();
			bool		IsItAlive();
			bool		IsRemoteThread();
			bool		IsGoodPriority();

			bool		HasSuspend();
			bool		HasDebugRegisters();

			bool		TrySuspend();
			bool		TryResume();

			void		SetCustomCode(DWORD dwCode);
			void		SetCustomName(const std::wstring& stName);

		private:
			CProcess*	m_pOwnerProcess;
			DWORD		m_dwThreadId;
			HANDLE		m_hThread;
			DWORD		m_dwThreadIdx;
			std::wstring	m_stCustomName;
	};
};
