#pragma once
#include <cpr/cpr.h>

namespace NoMercy
{
	enum EUploadFileTypes : uint8_t
	{
		FILE_TYPE_NULL,
		FILE_TYPE_LOG_FILE,
		FILE_TYPE_MINIDUMP_FILE,
		FILE_TYPE_ENCRYPTED_ZIP_FILE,
		FILE_TYPE_SCREENSHOT
	};

	using TOnCurlProgressCallback = std::function<void(uint32_t, uint32_t)>;

	class CCurlClient : public std::enable_shared_from_this <CCurlClient>
	{
	public:
		CCurlClient();
		virtual ~CCurlClient();
		
		int GetContentLength(const std::string& stURL);
		bool IsConnectionEstablished(const std::string& stURL) const;
		std::string GetWebSocketToken(const std::string& stURL) const;
		std::string GetUpdateRequest(const std::string& stURL, const std::string& stAuthUser = "", const std::string& stAuthPwd = "") const;
		bool UpdateFile(const std::string& stURL, HANDLE hFile, const TOnCurlProgressCallback& cb);
		bool SendNotification(const std::string& stURL, const std::string& stData) const;
		bool SendDataToRemoteServer(const std::wstring& stMessage, const std::vector <std::wstring>& vLogFiles);
		bool SendDataToRemoteServerWithLogs(const std::wstring& stMessage);

		auto GetCurlSession() const { return m_pkClient; };

	private:
		cpr::Session* m_pkClient;
	};
};
