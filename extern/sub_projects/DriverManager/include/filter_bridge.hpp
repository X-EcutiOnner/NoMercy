#pragma once
#include <windows.h>
#include <comdef.h>
#include <functional>
#include "../../../../source/Common/SharedTypes/FltTypes.h"
#include "filter_manager.hpp"

	static auto GetErrorDetails(HRESULT hr)
	{
		_com_error err(hr);
		return err.ErrorMessage();
	}

	template <typename PacketDataType, KbFltTypes PacketType>
	class CCommPortListener
	{
		using TCallback = std::function<void(CFilterHelper& Port, CMessagePacket <PacketDataType>& Message)>;

	public:
		CCommPortListener() :
			m_pPort("NoMercy"), m_hThread(nullptr), m_pCallback(nullptr), m_hrConnectStatus(ERROR_SUCCESS)
		{
			m_hSubscriptionEvent = CreateEventA(nullptr, TRUE, FALSE, nullptr);
		}
		~CCommPortListener()
		{
			Unsubscribe();
			CloseHandle(m_hSubscriptionEvent);
		}

		bool Subscribe(TCallback pListener)
		{
			if (m_hThread)
			{
				printf("Thread already exist!\n");
				return false;
			}

			if (!pListener)
			{
				printf("Listener callback function is null!\n");
				return false;
			}

			m_pCallback = pListener;

			m_hThread = CreateThread(nullptr, 0, ListenerThread, this, 0, nullptr);
			if (!m_hThread)
			{
				printf("CreateThread failed with error: %u\n", GetLastError());
				return false;
			}

			WaitForSingleObject(m_hSubscriptionEvent, 5000);

			if (!SUCCEEDED(m_hrConnectStatus))
			{
				printf("m_hrConnectStatus is not valid: %p\n", m_hrConnectStatus);
				CloseHandle(m_hThread);
				return false;
			}

			ResetEvent(m_hSubscriptionEvent);
			return true;
		}

		void Unsubscribe()
		{
			m_pPort.Disconnect();

			if (m_hThread)
			{
				if (WaitForSingleObject(m_hThread, 5000) == WAIT_TIMEOUT)
					TerminateThread(m_hThread, 0);

				CloseHandle(m_hThread);
			}
		}

	protected:
		static bool CallCallbackSafe(CCommPortListener* Self, CMessagePacket<PacketDataType>& Message)
		{
			if (Self->m_pCallback)
			{
				__try 
				{
					Self->m_pCallback(Self->m_pPort, Message);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) 
				{
					return false;
				}
			}
			return true;
		}

		static DWORD WINAPI ListenerThread(LPVOID lpParam)
		{
			auto Self = reinterpret_cast<CCommPortListener*>(lpParam);

			KB_FLT_CONTEXT Context = {};
			Context.Type = PacketType;
			Context.Client.ProcessId = GetCurrentProcessId();
			Context.Client.ThreadId = GetCurrentThreadId();

			Self->m_hrConnectStatus = Self->m_pPort.Connect(&Context, sizeof(Context));
			if (!SUCCEEDED(Self->m_hrConnectStatus))
			{
				printf("Can not connected to filter server Status: %p (%s)\n", Self->m_hrConnectStatus, GetErrorDetails(Self->m_hrConnectStatus));
				ExitThread(0);
			}

			SetEvent(Self->m_hSubscriptionEvent);

			HRESULT hr;
			do
			{
				CMessagePacket<PacketDataType> Message;
				hr = Self->m_pPort.Recv(*reinterpret_cast<CCommPortPacket*>(&Message));

				if (SUCCEEDED(hr))
				{
					CallCallbackSafe(Self, Message);
				}

				Sleep(10);
			} while (SUCCEEDED(hr));

			ExitThread(0);
			return 0;
		}

	private:
		HANDLE		m_hThread;
		HANDLE		m_hSubscriptionEvent;
		TCallback	m_pCallback;
		CFilterHelper	m_pPort;
		HRESULT		m_hrConnectStatus;
	};
