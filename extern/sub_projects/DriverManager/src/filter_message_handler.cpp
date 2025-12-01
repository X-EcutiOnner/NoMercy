#include "../include/filter_message_handler.hpp"

#define IS_VALID_SMART_PTR(ptr)		(ptr && ptr.get())

	CFilterMessageHandler::CFilterMessageHandler()
	{
		m_spObCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_OB_CALLBACK_INFO, KbObCallbacks>>();
		m_spProcessCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_PS_PROCESS_INFO, KbPsProcess>>();
		m_spThreadCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_PS_THREAD_INFO, KbPsThread>>();
		m_spImageCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_PS_IMAGE_INFO, KbPsImage>>();
		m_spDevHandleCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_CREATE_INFO, KbFltPreCreate>>();
		m_spDevIOCallbackFilter = std::make_shared<CCommPortListener <KB_FLT_DEVICE_CONTROL_INFO, KbFltPreDeviceControl>>();
	}
	CFilterMessageHandler::~CFilterMessageHandler()
	{
	}


	void CFilterMessageHandler::__OnObCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_OB_CALLBACK_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_OB_CALLBACK_INFO>(Message.GetData());

		auto from = Data->Target.ProcessId;
		auto to = Data->Client.ProcessId;
		auto newacs = Data->CreateResultAccess;
		auto oldacs = Data->CreateDesiredAccess;

//		printf("ObCallback; From: %lld -> To: %lld With access: %p\n", from, to, newacs);

		CReplyPacket<KB_FLT_OB_CALLBACK_INFO> Reply(Message, ERROR_SUCCESS, *Data);
		Port.Reply(Reply);
	}
	void CFilterMessageHandler::__OnProcessCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_PROCESS_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_PS_PROCESS_INFO>(Message.GetData());

		printf("Process Callback; IsCreated: %d PID: %lld Parent PID: %lld\n", Data->Created, Data->ProcessId, Data->ParentId);
	}
	void CFilterMessageHandler::__OnThreadCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_THREAD_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_PS_THREAD_INFO>(Message.GetData());

//		printf("Thread Callback; IsCreated: %d PID: %lld TID: %lld\n", Data->Created, Data->ProcessId, Data->ThreadId);
	}
	void CFilterMessageHandler::__OnImageCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_IMAGE_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_PS_IMAGE_INFO>(Message.GetData());

//		printf("Image Callback; PID: %lld Base: %p Name: %ls\n", Data->ProcessId, Data->BaseAddress, Data->FullImageName);
	}
	void CFilterMessageHandler::__OnDeviceCreateCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_CREATE_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_CREATE_INFO>(Message.GetData());

//		printf("Device handle Callback; PID: %lld TID: %lld Name: %ls\n", Data->ProcessId, Data->ThreadId, Data->Path);
	}
	void CFilterMessageHandler::__OnDeviceIOCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_DEVICE_CONTROL_INFO>& Message)
	{
		auto Data = static_cast<PKB_FLT_DEVICE_CONTROL_INFO>(Message.GetData());

//		printf("Device IO Callback; PID: %lld TID: %lld Name: %ls\n", Data->ProcessId, Data->ThreadId, Data->Path);
	}


	bool CFilterMessageHandler::Initialize()
	{
		// Validate instances
		if (!IS_VALID_SMART_PTR(m_spObCallbackFilter))
		{
            printf("EXIT_ERR_FILTER_OB_CALLBACK_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		if (!IS_VALID_SMART_PTR(m_spProcessCallbackFilter))
		{
            printf("EXIT_ERR_FILTER_PROCESS_CALLBACK_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		if (!IS_VALID_SMART_PTR(m_spThreadCallbackFilter))
		{
            printf("EXIT_ERR_FILTER_THREAD_CALLBACK_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		if (!IS_VALID_SMART_PTR(m_spImageCallbackFilter))
		{
            printf("EXIT_ERR_FILTER_IMAGE_CALLBACK_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		if (!IS_VALID_SMART_PTR(m_spDevHandleCallbackFilter))
		{
            printf("EXIT_ERR_FILTER_DEVICE_HANDLE_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		if (!IS_VALID_SMART_PTR(m_spDevIOCallbackFilter))
		{
	        printf("EXIT_ERR_FILTER_DEVICE_IO_WATCHER_ALLOC_FAIL error: %u\n", GetLastError());
			return false;
		}

		// Callback routines
		auto Status = m_spObCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnObCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_OB_CALLBACK_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		Status = m_spProcessCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnProcessCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_PROCESS_CALLBACK_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		Status = m_spThreadCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnThreadCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_THREAD_CALLBACK_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		Status = m_spImageCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnImageCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_IMAGE_CALLBACK_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		Status = m_spDevHandleCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnDeviceCreateCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_DEVICE_HANDLE_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		Status = m_spDevIOCallbackFilter->Subscribe(std::bind(&CFilterMessageHandler::__OnDeviceIOCallbackHandled, this, std::placeholders::_1, std::placeholders::_2));
		if (!Status)
		{
	        printf("EXIT_ERR_FILTER_DEVICE_IO_WATCHER_INIT_FAIL error: %u\n", GetLastError());
			return false;
		}

		return true;
	}

	void CFilterMessageHandler::Release()
	{
		m_spObCallbackFilter->Unsubscribe();
		m_spProcessCallbackFilter->Unsubscribe();
		m_spThreadCallbackFilter->Unsubscribe();
		m_spImageCallbackFilter->Unsubscribe();
		m_spDevHandleCallbackFilter->Unsubscribe();
		m_spDevIOCallbackFilter->Unsubscribe();
	}
