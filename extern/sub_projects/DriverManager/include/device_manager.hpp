#pragma once
#include <windows.h>
#include <string>
#include "../../../../source/Common/SharedTypes/WdkTypes.h"
#include "../../../../source/Common/SharedTypes/CtlTypes.h"

#define CTL_BASE (0x800)
#define IOCTL(Code, Method) (CTL_CODE(0x8000, (Code), Method, FILE_ANY_ACCESS))
#define EXTRACT_CTL_CODE(Ioctl)   ((unsigned short)(((Ioctl) & 0b0011111111111100) >> 2))
#define EXTRACT_CTL_METHOD(Ioctl) ((unsigned short)((Ioctl) & 0b11))

enum class EIOMessages
{
		NONE,

		// Driver management
		GetDriverApiVersion,		// 1
		GetDriverBuildInfo,			// 2
		GetHandlesCount,			// 3
		GetInitilizationStatus,		// 4
		InitializeCommunication,	// 5 Mersenne twister based simple key exchange

		// Custom
		PingPong,					// 6
		ForwardMessage,				// 7
		HeartbeatV1,				// 8
		BugCheck,					// 9
		OpenProcess,				// 10
		CloseProcessHandle,			// 11
		ReadMemory,					// 12
		ElevateProcess,				// 13
		QueryObjectName,			// 14

		MAXIMUM
};

class CDeviceHelper
{
public:
	CDeviceHelper(const std::string& stName);
	virtual ~CDeviceHelper();

	bool Create();
	bool Close();
	bool PingMsg();

protected:
	bool SendIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned = NULL, DWORD Method = METHOD_NEITHER);
	bool SendRawIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned = NULL);
	bool SendCryptedIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned);
	bool SendRequest(DWORD dwIndex, IN PVOID pInput = NULL, ULONG ulInputSize = 0, OUT PVOID pOutput = NULL, ULONG ulOutputSize = 0);

private:
	std::string m_stName;
	HANDLE m_hDriver;
};
