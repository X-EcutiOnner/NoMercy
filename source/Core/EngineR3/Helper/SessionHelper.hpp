#pragma once

namespace NoMercy
{
	static constexpr auto gsc_nWtsNameLength = 64;

	struct SWtsProcInfo
	{
		DWORD	session_id{ 0 };
		DWORD	process_id{ 0 };
		wchar_t	process_name[gsc_nWtsNameLength]{ '\0' };
		wchar_t	domain_name[gsc_nWtsNameLength]{ '\0' };
		wchar_t	user_name[gsc_nWtsNameLength]{ '\0' };
		SID		sid{ 0 };
	};
	struct SWtsSessionInfo
	{
		DWORD session_id{ 0 };
		wchar_t winstation_name[gsc_nWtsNameLength]{ '\0' };
		WTS_CONNECTSTATE_CLASS state;
	};

	class CSessionHelper
	{
	public:
		CSessionHelper(std::wstring stServerName = std::wstring());
		virtual ~CSessionHelper();

		bool		GetSessions(std::vector <SWtsSessionInfo>& sessions);
		uint32_t	GetProcesses(DWORD dwSessionId, SWtsProcInfo* pProcesses, uint32_t count);
		uint32_t	GetProcesses(SWtsProcInfo* pProcesses, uint32_t count);
		bool		GetSessionUser(DWORD dwSessionId, std::wstring& stUserName);

		bool		DisconnectSession(DWORD dwSessionId, bool bWait);
		bool		DisconnectSession(bool bWait);
		bool		LogoffSession(DWORD dwSessionId, bool bWait);
		bool		LogoffSession(bool bWait);
		bool		LogoffUser(const std::wstring& stUserName, bool bWait);

	protected:
		CSessionHelper(const CSessionHelper&);
		CSessionHelper& operator = (const CSessionHelper&);

		bool	OpenServer();
		void	CloseServer();

	private:
		std::wstring	m_server_name;
		HANDLE		m_server_handle;
	};
};
