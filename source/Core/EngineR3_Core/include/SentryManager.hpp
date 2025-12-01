#pragma once
#include <sentry.h>

namespace NoMercyCore
{
	class CSentryManager : public CSingleton <CSentryManager>
	{
	public:
		CSentryManager();
		virtual ~CSentryManager();

		CSentryManager(const CSentryManager&) = delete;
		CSentryManager(CSentryManager&&) noexcept = delete;
		CSentryManager& operator=(const CSentryManager&) = delete;
		CSentryManager& operator=(CSentryManager&&) noexcept = delete;

		bool Initialize();
		bool Release();

		auto IsInitialized() const { return m_bInitialized; };

		void SetUserData(const std::string& c_stHwid, const std::string& c_stSID, const std::string& c_stBootID, const std::string& c_stAntivirusInfo);
		void SendLog(const sentry_level_t nLevel, const std::string& c_stCategory, const std::string& c_stMessage);
		void AddAttachmentSafe(const std::wstring& wstAttachment, bool bTimeCheck);

	private:
		bool m_bInitialized;
		std::vector <std::string> m_vecContainer;
		bool m_bUserCreated;
		sentry_options_t* m_pSentryOptions;
		std::string m_stEnvironment;
	};
};