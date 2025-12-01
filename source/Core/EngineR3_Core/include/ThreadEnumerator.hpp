#pragma once

namespace NoMercyCore
{
	class CThreadEnumerator
	{
		public:
			CThreadEnumerator(DWORD dwAccess = MAXIMUM_ALLOWED);
			~CThreadEnumerator();

			HANDLE					FindThread(HANDLE hOwnerProcess, DWORD dwTargetTID);
			std::vector <HANDLE> 	EnumerateThreads(HANDLE hOwnerProcess);
			std::vector <HANDLE> 	EnumerateThreads();

		protected:
			void	CloseUselessHandles();

		private:
			DWORD					m_dwAccess;
			std::vector <HANDLE>	m_vHandleList;
	};
};
