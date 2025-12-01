#pragma once
#include <Windows.h>
#include <fltUser.h>
#include <string>

typedef struct _KERNEL_FLT_PING_DATA
{
	INT iMessage;
} SKernelFltPingData, * PKernelFltPingData;

class CCommPortPacket
{
public:
	CCommPortPacket() = default;
	~CCommPortPacket() = default;

	virtual PVOID GetHeader() = 0;
	virtual PVOID GetData() = 0;
	virtual ULONG GetSize() const = 0;
};

template <typename T>
class CMessagePacket : public CCommPortPacket
{
public:
	CMessagePacket() :
		Packet({})
	{
	}
	~CMessagePacket()
	{
	}

	PVOID GetHeader() override { return static_cast<PVOID>(&Packet.Header); }
	PVOID GetData() override { return static_cast<PVOID>(&Packet.Data); }
	ULONG GetSize() const override { return sizeof(Packet); }

	ULONG GetReplyLength() const { return Packet.Header.ReplyLength; }
	ULONGLONG GetMessageId() const { return Packet.Header.MessageId; }

private:
	struct
	{
		FILTER_MESSAGE_HEADER Header;
		T Data;
	} Packet;
};

template <typename T>
class CReplyPacket : public CCommPortPacket
{
public:
	CReplyPacket() :
		CCommPortPacket(), Packet({})
	{
	}
	CReplyPacket(CCommPortPacket& Message, ULONG Status) :
		CReplyPacket()
	{
		SetMessageId(static_cast<PFILTER_MESSAGE_HEADER>(Message.GetHeader())->MessageId);
		SetReplyStatus(Status);
	}
	CReplyPacket(CCommPortPacket& Message, ULONG Status, const T& Data) :
		CReplyPacket(Message, Status)
	{
		SetData(Data);
	}
	~CReplyPacket()
	{
	}

	PVOID GetData() override { return static_cast<PVOID>(&Packet.Data); }
	PVOID GetHeader() override { return static_cast<PVOID>(&Packet.Header); }
	ULONG GetSize() const override { return sizeof(Packet); }

	VOID SetData(const T& Data) { Packet.Data = Data; }
	VOID SetReplyStatus(NTSTATUS Status) { Packet.Header.Status = Status; }
	VOID SetMessageId(ULONGLONG MessageId) { Packet.Header.MessageId = MessageId; }
private:
	struct
	{
		FILTER_REPLY_HEADER Header;
		T Data;
	} Packet;
};

class CFilterHelper
{
public:
	CFilterHelper(const std::string& stPortName);
	~CFilterHelper();

	bool Connect(PVOID Context = nullptr, WORD SizeOfContext = 0);
	bool Disconnect();
	bool TestMsg();

	HRESULT Send(IN PVOID Input, DWORD InputSize, OUT PVOID Output, DWORD OutputSize, OUT OPTIONAL PULONG ReturnLength = NULL);
	HRESULT Recv(_Out_ CCommPortPacket& ReceivedMessage);
	HRESULT Reply(_In_ CCommPortPacket& ReplyMessage);

private:
	std::wstring m_wstPortName;
	HANDLE hPort;
	BOOL Connected;
};
