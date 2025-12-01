#pragma once
#include "../../source/Client/UserModule/include/Index.h"
#include "Metin2/Metin2_SDK.hpp"

namespace NoMercy
{
#define LOCK_MTX_SDK std::lock_guard <std::recursive_mutex> __lock(m_mutex)

	class CSDKManager : public std::enable_shared_from_this <CSDKManager>
	{
	public:
		CSDKManager();
		virtual ~CSDKManager();

		void ReleaseSDK();

		bool CreateMessageHandler(TNMCallback lpMessageHandler);
		bool ProcessClientMessage(int Code, LPCVOID c_lpMessage);
		bool SendMessageToClient(int Code, const char* c_szMessage, void* lpParam);
		bool SendSessionIDToClient(const char* c_szSessionID);

		void OnGameTick();

		auto IsGameInitialized() const  { LOCK_MTX_SDK; return m_bGameInitialized; };
		auto GetRenderEngine() const	{ LOCK_MTX_SDK; return m_stRenderEngine; };
		auto GetMetin2Manager()			{ LOCK_MTX_SDK; return m_spMetin2Mgr; };

		auto GetPlatformName() const	{ LOCK_MTX_SDK; return wstPlatformName; };
		auto GetPlayerName() const		{ LOCK_MTX_SDK; return wstPlayerName; };

	private:
		mutable std::recursive_mutex m_mutex;
		
		TNMCallback m_pMessageHandler;
		bool m_bGameInitialized;
		bool m_bSessionIDSent;

		std::wstring wstPlatformName;
		std::wstring wstPlayerName;

		std::wstring m_stRenderEngine;

		std::shared_ptr <CMetin2SDKMgr>	m_spMetin2Mgr;
	};
};
