#pragma once

namespace NoMercyCore
{
	class CThreadEnumeratorNT
	{
		public:
			CThreadEnumeratorNT(DWORD dwProcessId);
			~CThreadEnumeratorNT();

			LPVOID GetProcInfo();
			LPVOID GetThreadList(LPVOID procInfo);
			DWORD  GetThreadCount(LPVOID procInfo);

			LPVOID FindThread(LPVOID procInfo, DWORD dwThreadId);

		protected:
			BYTE* InitializeQuery();

		private:
			DWORD  m_dwProcessId;
			BYTE* m_Cap;
	};
};
