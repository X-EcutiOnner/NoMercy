#include "../../PCH.hpp"
#include "../../Index.hpp"
#include "../../Application.hpp"
#include "../SDKManager.hpp"
#include "../Metin2/Metin2_SDK.hpp"
#include "../../Common/MTRandom.hpp"

namespace NoMercy
{
	// TODO: ORDER
#pragma pack(push)
#pragma pack(1)
	struct SHeartbeatV1Packet
	{
		uint8_t header{ 0 };
		uint32_t key{ 0 };
		uint64_t hash{ 0 };
	};

	struct SHeartbeatV2Packet
	{
		uint8_t header{ 0 };
		char key[1024]{ 0 };
	};
#pragma pack(pop)

	inline std::string EncryptHeartbeatValue(const std::wstring& stValue)
	{
		SDK_LOG(LL_SYS, L"Heartbeat encryption started");

		const auto key = CApplication::Instance().DataLoaderInstance()->GetRSAPublicKey();
		if (!IS_VALID_SMART_PTR(key))
		{
			SDK_LOG(LL_ERR, L"RSA key data is not valid");
			return {};
		}
		SDK_LOG(LL_SYS, L"RSA key handled");

		std::stringstream ss;
		try
		{
			// Treat the message as a big endian byte array
			auto m = CryptoPP::Integer((const byte*)stValue.data(), stValue.size());
			SDK_LOG(LL_SYS, L"Value converted to byte array");

			// Encrypt
			auto c = key->ApplyFunction(m);
			SDK_LOG(LL_SYS, L"Value encrypted");

			// Encode
			ss << std::hex << c;
		}
		catch (const CryptoPP::Exception& ex)
		{
			SDK_LOG(LL_ERR, L"Encrypt heartbeat failed, Error: %hs", ex.what());
			return {};
		}

		const auto val = ss.str();
		SDK_LOG(LL_SYS, L"Value: %s", val.c_str());
		return val;
	}

	void CMetin2SDKMgr::OnHeartbeatTick()
	{
//		__PROTECTOR_START__("heartbeat");

		LOCK_MTX_M2;

		SDK_LOG(LL_SYS, L"Heartbeat event started");

		const auto dwTimerDiff = m_pHeartbeatCheckTimer.diff();
		SDK_LOG(LL_SYS, L"Heartbeat timer diff: %u", dwTimerDiff);

		static const auto sc_dwHeartbeatInterval = NoMercyCore::CApplication::Instance().DataInstance()->GetHeartbeatInterval();
		if (dwTimerDiff < sc_dwHeartbeatInterval)
			return;

		// Sanity check
		if (!m_pGetPhase || !m_pGetVID || !m_pSend || !m_pSendSequence)
		{
			SDK_LOG(LL_CRI, L"Missing game proxy function detected: %d/%d/%d/%d",
				m_pGetPhase ? 1 : 0, m_pGetVID ? 1 : 0, m_pSend ? 1 : 0, m_pSendSequence ? 1 : 0
			);
			CApplication::Instance().OnCloseRequest(EXIT_ERR_HEARTBEAT_SETUP_FAIL, 1);
			return;
		}

		SDK_LOG(LL_SYS, L"Heartbeat functions are valid");

		// Self integrity check
		if (CApplication::Instance().WatchdogInstance()->IsInitialized())
		{
			const auto dwLastCheckTime = CApplication::Instance().WatchdogInstance()->GetLastCheckTime();
			const auto dwCurrentTime = CApplication::Instance().FunctionsInstance()->GetCurrentTimestamp();
			const auto dwTimeDif = dwCurrentTime - dwLastCheckTime;

			if (dwTimeDif > 30000)
			{
				SDK_LOG(LL_ERR, L"Watchdog check timeout. Dif: %u Last check: %u", dwTimeDif, dwLastCheckTime);
				CApplication::Instance().OnCloseRequest(EXIT_ERR_WATCHDOG_TIMEOUT, dwTimeDif);
				return;
			}
		}

		// Heartbeat routine
		static DWORD dwTmpVID = 0;
		{
			auto dwVID = GetVID();
			SDK_LOG(LL_SYS, L"Current VID: %u", dwVID);

			if (dwVID)
			{
				const auto dwPhase = GetPhase();
				SDK_LOG(LL_SYS, L"Current Phase: %u", dwPhase);

				if (dwPhase == 6)
				{
					{
						// Changed character, reset value generator
						if (dwTmpVID != dwVID)
						{
							SDK_LOG(LL_SYS, L"VID reset");
							dwTmpVID = dwVID;

							m_spRandom.reset(new CMTRandom(dwVID));
						}

						const auto val = m_spRandom->next();
						SDK_LOG(LL_SYS, L"Heartbeat key: %u", val);

						if (m_nHeartbeatType == 1) // Basic
						{
							const auto seed = NoMercyCore::CApplication::Instance().DataInstance()->GetHeartbeatSeed();
							SDK_LOG(LL_SYS, L"Heartbeat seed: %u", seed);

							const auto hash = XXH64(&val, sizeof(val), seed);
							SDK_LOG(LL_SYS, L"Heartbeat hash: %llu", hash);

							SHeartbeatV1Packet packet{ 0 };
							packet.header = 221;
							packet.key = val;
							packet.hash = hash;

							auto bRet = Send((const char*)&packet, sizeof(packet));
							SDK_LOG(LL_SYS, L"Send result: %d", bRet ? 1 : 0);
						}
						else // Enchanted
						{
							const auto stValue = std::to_wstring(val);
							const auto stCrypted = EncryptHeartbeatValue(stValue);
							if (stCrypted.empty())
							{
								CApplication::Instance().OnCloseRequest(EXIT_ERR_HEARTBEAT_CRYPT_FAIL, 0);
								return;
							}
							else if (stCrypted.size() > 1024)
							{
								CApplication::Instance().OnCloseRequest(EXIT_ERR_HEARTBEAT_OVERFLOW, stCrypted.size());
								return;
							}

							SHeartbeatV2Packet packet{ 0 };
							packet.header = 222;
							strncpy(packet.key, stCrypted.c_str(), stCrypted.size());

							auto bRet = Send((const char*)&packet, sizeof(packet));
							SDK_LOG(LL_SYS, L"Send result: %d", bRet ? 1 : 0);
						}
					}
				}
			}
		}

		m_pHeartbeatCheckTimer.reset();
//		__PROTECTOR_END__("heartbeat");
	}

	VOID CALLBACK HeartbeatRoutine(PVOID lpParam, BOOLEAN TimerOrWaitFired)
	{
				/*
		const auto spSdkHelper = CApplication::Instance().SDKHelperInstance();
		if (IS_VALID_SMART_PTR(spSdkHelper))
		{
			const auto m2 = spSdkHelper->GetMetin2Manager();
			if (IS_VALID_SMART_PTR(m2))
			{
				SDK_LOG(LL_SYS, L"OnHeartbeatTick: %d - %d Phase: %u", m2->IsHeartbeatEnabled() ? 1 : 0, m2->IsInitialized() ? 1 : 0, m2->GetPhase());
				* TODO
				if (m2->IsHeartbeatEnabled() && m2->IsInitialized())
				{
					m2->OnHeartbeatTick();
				}
			}
		}
				*/
	}

	bool CMetin2SDKMgr::InitializeHeartbeatTimer()
	{
		LOCK_MTX_M2;

		auto hTimerQueue = CApplication::Instance().GetTimerQueueHandle();
		if (!IS_VALID_HANDLE(hTimerQueue))
		{
			SDK_LOG(LL_ERR, L"Timer queue is not valid");
			return false;
		}

		const auto ntStatus = g_winAPIs->RtlCreateTimer(hTimerQueue, &m_hHeartbeatTimer, HeartbeatRoutine, NULL, 1000, 5000, WT_EXECUTEDEFAULT);
		if (!NT_SUCCESS(ntStatus) || !IS_VALID_HANDLE(m_hHeartbeatTimer))
		{
			SDK_LOG(LL_ERR, L"RtlCreateTimer failed with error: %p", ntStatus);
			return false;
		}

		SDK_LOG(LL_SYS, L"Heartbeat timer initialized!");
		return true;
	}
	void CMetin2SDKMgr::ReleaseHeartbeatTimer()
	{
		LOCK_MTX_M2;

		auto hTimerQueue = CApplication::Instance().GetTimerQueueHandle();
		if (IS_VALID_HANDLE(hTimerQueue) && IS_VALID_HANDLE(m_hHeartbeatTimer))
		{
			g_winAPIs->RtlDeleteTimer(hTimerQueue, m_hHeartbeatTimer, INVALID_HANDLE_VALUE);
			m_hHeartbeatTimer = INVALID_HANDLE_VALUE;
		}
	}
}
