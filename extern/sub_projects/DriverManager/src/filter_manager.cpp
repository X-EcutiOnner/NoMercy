#include "../include/filter_manager.hpp"

CFilterHelper::CFilterHelper(const std::string& stPortName) :
	hPort(NULL), Connected(FALSE)
{
	m_wstPortName = std::wstring(stPortName.begin(), stPortName.end());
}
CFilterHelper::~CFilterHelper()
{
	Disconnect();
}


bool CFilterHelper::Connect(PVOID Context, WORD SizeOfContext)
{
	const auto c_wstDriverName = L"\\" + m_wstPortName;
	HRESULT Status = FilterConnectCommunicationPort(c_wstDriverName.c_str(), 0, Context, SizeOfContext, NULL, &hPort);

	Connected = Status == S_OK;
	if (!Connected)
		printf("FilterConnectCommunicationPort(%ls) failed with error code: %p\n", c_wstDriverName.c_str(), Status);
	else
		printf("FilterConnectCommunicationPort(%ls) succeeded\n", c_wstDriverName.c_str());
		
	return Connected;
}

bool CFilterHelper::Disconnect()
{
	if (hPort)
		return CloseHandle(hPort);
	return true;
}

bool CFilterHelper::TestMsg()
{
	if (!hPort || hPort == INVALID_HANDLE_VALUE)
		return false;

	SKernelFltPingData pData = { 0 };
	pData.iMessage = 0;
	return SUCCEEDED(Send(&pData, sizeof(pData), &pData, sizeof(pData)));
}


HRESULT CFilterHelper::Send(IN PVOID Input, DWORD InputSize, OUT PVOID Output, DWORD OutputSize, OUT OPTIONAL PULONG ReturnLength)
{
	DWORD Returned = 0;
	HRESULT Status = FilterSendMessage(hPort, Input, InputSize, Output, OutputSize, &Returned);

	if (ReturnLength)
		*ReturnLength = Returned;
	return Status;
}

HRESULT CFilterHelper::Recv(_Out_ CCommPortPacket& ReceivedMessage)
{
	return FilterGetMessage(hPort, static_cast<PFILTER_MESSAGE_HEADER>(ReceivedMessage.GetHeader()), ReceivedMessage.GetSize(), NULL);
}

HRESULT CFilterHelper::Reply(_In_ CCommPortPacket& ReplyMessage)
{
	return FilterReplyMessage(hPort, static_cast<PFILTER_REPLY_HEADER>(ReplyMessage.GetHeader()), ReplyMessage.GetSize());
}
