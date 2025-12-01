#pragma once
#include "filter_bridge.hpp"
#include "filter_manager.hpp"
#include "../../../../source/Common/SharedTypes/WdkTypes.h"
#include "../../../../source/Common/SharedTypes/CtlTypes.h"
#include <memory>

class CFilterMessageHandler : std::enable_shared_from_this <CFilterMessageHandler>
{
public:
	CFilterMessageHandler();
	virtual ~CFilterMessageHandler();

	bool Initialize();
	void Release();

protected:
	void __OnObCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_OB_CALLBACK_INFO>& Message);
	void __OnProcessCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_PROCESS_INFO>& Message);
	void __OnThreadCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_THREAD_INFO>& Message);
	void __OnImageCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_PS_IMAGE_INFO>& Message);
	void __OnDeviceCreateCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_CREATE_INFO>& Message);
	void __OnDeviceIOCallbackHandled(CFilterHelper& Port, CMessagePacket <KB_FLT_DEVICE_CONTROL_INFO>& Message);

private:
	std::shared_ptr <CCommPortListener <KB_FLT_OB_CALLBACK_INFO, KbObCallbacks>>			m_spObCallbackFilter;
	std::shared_ptr <CCommPortListener <KB_FLT_PS_PROCESS_INFO, KbPsProcess>>				m_spProcessCallbackFilter;
	std::shared_ptr <CCommPortListener <KB_FLT_PS_THREAD_INFO, KbPsThread>>					m_spThreadCallbackFilter;
	std::shared_ptr <CCommPortListener <KB_FLT_PS_IMAGE_INFO, KbPsImage>>					m_spImageCallbackFilter;
	std::shared_ptr <CCommPortListener <KB_FLT_CREATE_INFO, KbFltPreCreate>>				m_spDevHandleCallbackFilter;
	std::shared_ptr <CCommPortListener <KB_FLT_DEVICE_CONTROL_INFO, KbFltPreDeviceControl>> m_spDevIOCallbackFilter;
};
