#pragma once

namespace NoMercy
{
	class CSelfThreadIdentifier : public std::enable_shared_from_this <CSelfThreadIdentifier>
	{
	public:
		CSelfThreadIdentifier();
		virtual ~CSelfThreadIdentifier() = default;

	public:
		DWORD GetLastCheckTime(DWORD dwThreadCode);
		void SetLastCheckTime(DWORD dwThreadCode, DWORD dwTime);

		void IncreaseThreadTick(DWORD dwThreadCode);
		void DecreaseThreadTick(DWORD dwThreadCode);
		void ReleaseThreadTicks(DWORD dwThreadCode);
		DWORD GetThreadTick(DWORD dwThreadCode);

		void InitializeThreadChecks(DWORD dwThreadCode);

		bool	InitThreadTickChecker();
		void	ReleaseThreadTickChecker();

		bool	IsTickCheckerThreadIntegrityCorrupted();
		void	CheckSelfThreads();

	protected:
		bool CheckThreadIntegrity(HANDLE hThread, LPDWORD pdwErrorCode);

	private:
		std::map <DWORD, DWORD> m_threadTimeMap;
		std::map <DWORD, DWORD> m_threadTicksMap;
	};
};
