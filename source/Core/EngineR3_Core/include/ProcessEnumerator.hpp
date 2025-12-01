#pragma once

namespace NoMercyCore
{
	class CProcessEnumerator
	{
		public:
			CProcessEnumerator(DWORD dwAccess = MAXIMUM_ALLOWED);
			~CProcessEnumerator();

			HANDLE					FindProcessFromPID(DWORD dwProcessID, bool bAliveOnly = false);
			std::vector <HANDLE> 	EnumerateProcesses(bool bAliveOnly = false);

		protected:
			void	CloseUselessHandles();

		private:
			DWORD					m_dwAccess;
			std::vector <HANDLE>	m_vecCreatedHandleList;
			std::vector <HANDLE>	m_vecReturnedHandleList;
	};
};
