#pragma once
#include <cstdint>
#pragma warning(push) 
#pragma warning(disable: 4127 4244 4267)
#include <websocketpp/config/asio_client.hpp>
#include <websocketpp/client.hpp>
#pragma warning(pop) 
#include "../Crypto/SealedBox.hpp"

namespace NoMercy
{
	struct SWsConnFailData
	{
		uint32_t state{ 0 };
		uint32_t local_code{ 0 };
		char local_reason[1024]{ '\0' };
		uint32_t remote_code{ 0 };
		char remote_reason[1024]{ '\0' };
		uint32_t err_code{ 0 };
		char err_msg[1024]{ '\0' };
	};

	enum class EWSIncMsgErrCodes : uint8_t
	{
		NONE,
		UNDEFINED_MESSAGE_ID,
		CAN_CONNECT_RESULT,
		LICENSE_RESULT,
		NM_CONFIG_RESULT,
		NM_CONFIG_PARSE_1,
		NM_CONFIG_PARSE_2,
		NM_CONFIG_PARSE_3,
		USER_AUTH_RESULT,
		NM_VALIDATION_RESULT,
		GS_VALIDATION_RESULT,
		CDB_REQUEST_RESULT,
		CDB_PARSE_RESULT_1,
		CDB_PARSE_RESULT_2,
		INIT_SUCCESS_RESULT,
		INIT_FAIL_RESULT,
		CLOSE_NOTIFICATION_RESULT,
		ASSET_VALIDATION_RESULT,
		CHEAT_DETECT_RESULT,
		USER_TELEMETRY_RESULT,
		CDB_VALIDATION_RESULT,
		BROADCAST_MESSAGE,
		BINARY_PROCESS_RESULT,
		HEARTBEAT_RESULT_1,
		HEARTBEAT_RESULT_2,
		HEARTBEAT_RESULT_3,
		HEARTBEAT_RESULT_4,
		HEARTBEAT_RESULT_5,
		SYS_TELEMETRY_RESULT_1,
		SYS_TELEMETRY_RESULT_2,
		SYS_TELEMETRY_RESULT_3,
		SYS_TELEMETRY_RESULT_4,
		SYS_TELEMETRY_RESULT_5,
		SYS_TELEMETRY_RESULT_6,
		IDLE_CLIENT_RESULT
	};

	enum EWSIncomingMessages
	{
		WS_INCOMING_MESSAGE_TYPE_NULL = 0,
		WS_INCOMING_MESSAGE_TYPE_CAN_CONNECT_RESULT = 1,
		WS_INCOMING_MESSAGE_TYPE_LICENSE_RESULT = 2,
		WS_INCOMING_MESSAGE_TYPE_NOMERCY_CONFIG_RESULT = 3,
		WS_INCOMING_MESSAGE_TYPE_USER_AUTH_RESULT = 4,
		WS_INCOMING_MESSAGE_TYPE_NOMERCY_VALIDATION_RESULT = 5,
		WS_INCOMING_MESSAGE_TYPE_GAME_SERVER_VALIDATION_RESULT = 6,
		WS_INCOMING_MESSAGE_TYPE_CHEAT_DB_REQUEST_RESULT = 7,
		WS_INCOMING_MESSAGE_TYPE_INIT_SUCCESS_NOTIFICATION_RESULT = 8,
		WS_INCOMING_MESSAGE_TYPE_INIT_FAILURE_NOTIFICATION_RESULT = 9,
		WS_INCOMING_MESSAGE_TYPE_CLIENT_CLOSE_NOTIFICATION_RESULT = 10,
		WS_INCOMING_MESSAGE_TYPE_GAME_ASSET_VALIDATION_RESULT = 11,
		WS_INCOMING_MESSAGE_TYPE_CHEAT_DETECTION_RESULT = 12,
		WS_INCOMING_MESSAGE_TYPE_TELEMETRY_RESULT = 13,
		WS_INCOMING_MESSAGE_TYPE_CHEAT_DB_VALIDATION_RESULT = 14,
		// 15: RESERVED
		WS_INCOMING_MESSAGE_TYPE_SYSTEM_TELEMETRY_REQUEST = 16,
		WS_INCOMING_MESSAGE_TYPE_SCAN_CACHE_REQUEST = 18, // TODO
		WS_INCOMING_MESSAGE_TYPE_BROADCAST = 19,
		WS_INCOMING_MESSAGE_TYPE_UNALLOWED_CLIENT = 20,
		WS_INCOMING_MESSAGE_TYPE_IDLE_CLIENT = 21,
		WS_INCOMING_MESSAGE_TYPE_SIGNAL_BINARY_PROCESS_COMPLETED = 101,
		WS_INCOMING_MESSAGE_TYPE_SIGNAL_HEARTBEAT_REQUEST = 102,
		WS_INCOMING_MESSAGE_TYPE_ADMIN_LIST_SOCKETS_RESULT = 1001,
		WS_INCOMING_MESSAGE_TYPE_ADMIN_REQUEST_RESULT = 1002,
		WS_INCOMING_MESSAGE_TYPE_ADMIN_REQUEST = 1003
	};
	enum EWSOutgoingMessages
	{
		WS_OUTGOING_MESSAGE_TYPE_NULL = 0,
		WS_OUTGOING_MESSAGE_TYPE_CAN_CONNECT = 1,
		WS_OUTGOING_MESSAGE_TYPE_LICENSE = 2,
		WS_OUTGOING_MESSAGE_TYPE_NOMERCY_CONFIG = 3,
		WS_OUTGOING_MESSAGE_TYPE_USER_AUTH = 4,
		WS_OUTGOING_MESSAGE_TYPE_NOMERCY_VALIDATION = 5,
		WS_OUTGOING_MESSAGE_TYPE_GAME_SERVER_VALIDATION = 6,
		WS_OUTGOING_MESSAGE_TYPE_CHEAT_DB_REQUEST = 7,
		WS_OUTGOING_MESSAGE_TYPE_INIT_SUCCESS_NOTIFICATION = 8,
		WS_OUTGOING_MESSAGE_TYPE_INIT_FAILURE_NOTIFICATION = 9,
		WS_OUTGOING_MESSAGE_TYPE_CLIENT_CLOSE_NOTIFICATION = 10,
		WS_OUTGOING_MESSAGE_TYPE_GAME_ASSET_VALIDATION = 11,
		WS_OUTGOING_MESSAGE_TYPE_CHEAT_DETECTION = 12,
		WS_OUTGOING_MESSAGE_TYPE_TELEMETRY = 13,
		WS_OUTGOING_MESSAGE_TYPE_CHEAT_DB_VALIDATION = 14,
		WS_OUTGOING_MESSAGE_TYPE_HEARTBEAT = 15,
		WS_OUTGOING_MESSAGE_TYPE_SYSTEM_TELEMETRY_RESPONSE = 16,
		WS_OUTGOING_MESSAGE_TYPE_SCAN_CACHE_RESPONSE = 18, // TODO
		WS_OUTGOING_MESSAGE_TYPE_CHEAT_DETAILS = 19,
		WS_OUTGOING_MESSAGE_TYPE_BINARY_HANDLE = 101,
		WS_OUTGOING_MESSAGE_TYPE_ADMIN_LIST_SOCKETS = 1001,
		WS_OUTGOING_MESSAGE_TYPE_ADMIN_REQUEST = 1002,
		WS_OUTGOING_MESSAGE_TYPE_ADMIN_REQUEST_RESULT = 1003
	};

#if (WEBSOCKET_USE_SSL == TRUE)
	using client = websocketpp::client <websocketpp::config::asio_tls_client>;
	using context_ptr = std::shared_ptr <asio::ssl::context>;
#else
	using client = websocketpp::client <websocketpp::config::asio_client>;
#endif

	using message_ptr = websocketpp::config::asio_client::message_type::ptr;

	class CWebSocketClient : public std::enable_shared_from_this <CWebSocketClient>
	{
	public:
		CWebSocketClient(const std::string& host, const uint32_t port);
		virtual ~CWebSocketClient();

		auto IsInitialized() const { return m_bInitialized; };
		auto IsConnected() const { return !m_bConnectionLost; };

		bool InitWebSocketThread();
		void ShutdownWebSocketConnection();

		void send_message(const std::wstring& message, const bool queued = false);

		void send_can_connect_message();
		void send_initilization_success_message();
		void send_initilization_failure_message(const uint32_t error_code, const uint32_t system_error_code);
		void send_client_close_notification_message(const uint32_t req_id, const uint32_t sub_code, const std::wstring& details);
		void send_game_asset_validation_message(const std::map <std::wstring /* filename */, std::wstring /* hash */> files);
		void send_cheat_detection_message(const std::wstring& ref_id, const std::wstring& cheat_id, const std::wstring& sub_id, const std::wstring& custom_message, const std::vector <std::wstring>& screenshots);
		void send_user_telemetry_message(const std::wstring& message);
		void send_cheat_db_validation_message(const uint32_t db_version);
		void send_heartbeat_response(const uint8_t status, const uint8_t key);

		// Setters
		void SetIdleClient(const bool state) { m_bIsIdleClient = state; };

	protected:
		bool create_jwt(std::wstring& wstToken);
		void verify_jwt();

		void send_license_message();
		void send_nomercy_config_message();
		void send_user_auth_message();
		void send_nomercy_validation_message();
		void send_game_server_validation_message();
		void send_cheat_db_request_message();

		std::wstring encrpyt_message(const std::wstring& in);
		std::wstring decrypt_message(const std::wstring& in);

		// Custom callbacks
		void on_binary_handle(const std::string& buffer);
		void on_error_message(const int32_t id, const std::wstring& msg);
		void on_custom_message(const int32_t id, rapidjson::GenericValue<UTF16<>>&& val);

		// Websocketpp callbacks
		void on_open(websocketpp::connection_hdl hdl);
		void on_fail(websocketpp::connection_hdl hdl);
		void on_message(websocketpp::connection_hdl hdl, message_ptr msg);
		void on_close(websocketpp::connection_hdl hdl);
		bool on_ping(websocketpp::connection_hdl hdl, std::string msg);

	protected:
		void __CreateConnection();

		DWORD					SetupConnection(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		websocketpp::connection_hdl m_connection;

		std::wstring m_wstAddress;
		bool m_bInitialized;
		bool m_bConnectionFailed;
		bool m_bConnectionLost;
		bool m_bIsRawTest;
		bool m_bIsIdleClient;
		std::shared_ptr <SKeyPair> m_spKeyPair;
		std::string m_stToken;
		std::wstring m_wstHost;
		uint32_t m_dwPort;
		client m_client;
		uint32_t m_dwLastConnectionTime;
		uint32_t m_dwDisconectCounter;
		uint32_t m_dwLastDisconectTime;
	};
};
