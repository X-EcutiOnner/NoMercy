#pragma once
#include "Defines.hpp"
#include "WMI/MultiThreadedModel.hpp"
#include "WMI/Thread.hpp"
#include "WMI/WbemServices.hpp"
#include "WMI/WbemLocator.hpp"
#include "WMI/WbemObjectSink.hpp"

namespace NoMercyCore
{
	class ComStr
	{
	public:
		ComStr(const std::string& in) : m_com_str(nullptr)
		{
			Initialize(std::wstring(in.begin(), in.end()));
		}
		ComStr(const std::wstring& in) : m_com_str(nullptr)
		{
			Initialize(in);
		}
		~ComStr()
		{
			if (m_com_str) SysFreeString(m_com_str);
		}

		operator BSTR ()
		{
			return m_com_str;
		}

	protected:
		void Initialize(const std::wstring& in)
		{
			if (!in.empty())
				m_com_str = SysAllocString(in.c_str());
		}

	private:
		BSTR m_com_str;
	};
	
	
	class CWMIAsyncQueryThreadImpl : public SOL::Thread
	{
	public:
		CWMIAsyncQueryThreadImpl() :
			m_thread_model(nullptr), m_locator(nullptr), m_services(nullptr), m_object_sink(nullptr)
		{
		}
		~CWMIAsyncQueryThreadImpl()
		{
			if (m_object_sink)
			{
				delete m_object_sink;
				m_object_sink = nullptr;
			}
			if (m_services)
			{
				delete m_services;
				m_services = nullptr;
			}
			if (m_locator)
			{
				delete m_locator;
				m_locator = nullptr;
			}
			if (m_thread_model)
			{
				delete m_thread_model;
				m_thread_model = nullptr;
			}
		}

		void stop()
		{
			if (m_services)
				m_services->cancelAsyncCall(m_object_sink);
		}

		bool initialize(const std::wstring& wstQuery, const SOL::TWbemCallbackFn& callback)
		{
			try
			{
				m_thread_model = new(std::nothrow) SOL::MultiThreadedModel();
				if (!m_thread_model)
				{
					WMI_LOG(LL_ERR, L"m_thread_model allocation failed!");
					return false;
				}

				m_locator = new(std::nothrow) SOL::WbemLocator();
				if (!m_locator)
				{
					WMI_LOG(LL_ERR, L"m_locator allocation failed!");
					return false;
				}
				
				m_services = new(std::nothrow) SOL::WbemServices(m_locator->connectServer(xorstr_(L"ROOT\\CIMV2")));
				if (!m_services)
				{
					WMI_LOG(LL_ERR, L"m_services allocation failed!");
					return false;
				}

				m_object_sink = new(std::nothrow) SOL::WbemObjectSink(callback);
				if (!m_object_sink)
				{
					WMI_LOG(LL_ERR, L"m_object_sink allocation failed!");
					return false;
				}

				HRESULT hr = S_OK;
				if (FAILED(hr = m_services->execNotificationQueryAsync((const BSTR)wstQuery.c_str(), m_object_sink)))
				{
					WMI_LOG(LL_ERR, L"execNotificationQueryAsync failed with status: %p", hr);
					return false;
				}

				WMI_LOG(LL_SYS, L"Async query initialized!");
			}
			catch (const SOL::Exception& ex)
			{
				WMI_LOG(LL_ERR, L"CWMIAsyncQueryThreadImpl::initialize exception handled! SOL exception: %hs", ex.getErrorMessage());
				return false;
			}
			catch (const std::exception& ex)
			{
				WMI_LOG(LL_ERR, L"CWMIAsyncQueryThreadImpl::initialize exception handled! STD exception: %hs", ex.what());
				return false;
			}
			catch (HRESULT hResult)
			{
				WMI_LOG(LL_ERR, L"CWMIAsyncQueryThreadImpl::initialize exception handled! hResult: %p", hResult);
				return false;
			}
			catch (...)
			{
				WMI_LOG(LL_ERR, L"CWMIAsyncQueryThreadImpl::initialize unhandled exception throwned!");
				return false;
			}

			return true;
		}

		HANDLE get_thread() const
		{
			return this->getHandle();
		}

		DWORD get_threadid() const
		{
			return this->getThreadId();
		}

	private:
		SOL::MultiThreadedModel* 	m_thread_model;
		SOL::WbemLocator* 			m_locator;
		SOL::WbemServices* 			m_services;
		SOL::WbemObjectSink* 		m_object_sink;
	};
	

	using TWmiDataContainer 	= std::map <std::wstring, std::wstring>;
	using TWmiCallback 			= std::function<void(TWmiDataContainer)>;
	using TWmiAsyncCallback 	= std::function<void(wchar_t* str)>;
	using TWmiOnFailCallback 	= std::function<void(HRESULT)>;

	class CWMIHelper : public CSingleton <CWMIHelper>
	{
	public:
		CWMIHelper();
		virtual ~CWMIHelper();

		bool CheckWMIIntegirty();

		HANDLE CreateAsyncWatcherThread(const std::wstring& wstQuery, const TWmiAsyncCallback& fnCallback);
		void TerminateThreads();
		void TerminateAsyncWatcherThread(DWORD dwThreadID);
		void StopWatcher(DWORD dwThreadID);

		bool ExecuteQuery(const std::wstring& wstNamespace, const std::wstring& wstQuery, const TWmiCallback& fnCallback, const TWmiOnFailCallback& fnOnFail = nullptr);

	private:
		std::map <DWORD, SOL::Thread*> m_mapAsyncThreads;
		std::map <DWORD, HANDLE> m_mapAsyncThreadWaitObjects;
	};
};
