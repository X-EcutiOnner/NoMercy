#include "../include/device_manager.hpp"

#define NM_IOCTL_MAGIC 'NGCB'

static void __EncryptBuffer(uint8_t * lpBuf, size_t dwSize, uint8_t pKey)
{
	for (size_t i = 0; i < dwSize; i++)
	{
		lpBuf[i] ^= (uint8_t)i + 8;
		lpBuf[i] -= (uint8_t)i;
		lpBuf[i] ^= pKey;
	}
}


CDeviceHelper::CDeviceHelper(const std::string& stName) :
	m_hDriver(INVALID_HANDLE_VALUE), m_stName(stName)
{
}
CDeviceHelper::~CDeviceHelper()
{
	if (m_hDriver && m_hDriver != INVALID_HANDLE_VALUE)
		CloseHandle(m_hDriver);
}


bool CDeviceHelper::Create()
{
	const auto c_stDriverName = "\\\\.\\" + m_stName;
	m_hDriver = CreateFileA(c_stDriverName.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, FILE_ATTRIBUTE_SYSTEM, 0);
	return (m_hDriver && m_hDriver != INVALID_HANDLE_VALUE);
}
bool CDeviceHelper::Close()
{
	return CloseHandle(m_hDriver);
}


bool CDeviceHelper::PingMsg()
{
	SPingPongContext ctxOUT = { 0 };
	SPingPongContext ctxIN = { 0 };
	ctxIN.ulMessage = 1337;

	const auto bRet = SendRequest((DWORD)EIOMessages::PingPong, &ctxIN, sizeof(ctxIN), &ctxOUT, sizeof(ctxOUT));

	const auto dwProcessID = GetCurrentProcessId();
	printf("IO completed! Result: %d Completed: %d Msg: %d/%d PID: %u\n", bRet, ctxOUT.bCompleted, ctxIN.ulMessage, ctxOUT.ulMessage, dwProcessID);

	if (bRet && ctxOUT.bCompleted)
	{
		const auto bCorrect = ctxOUT.ulMessage ^ dwProcessID == 1337;
		return bCorrect;
	}

	return false;
}


bool CDeviceHelper::SendRawIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned)
{
	if (!m_hDriver || m_hDriver == INVALID_HANDLE_VALUE)
	{
		printf("Target device handle is not valid!!! Handle: %p Error: %u\n", m_hDriver, GetLastError());
		return false;
	}

	auto dwReturned = 0UL;
	auto bStatus = DeviceIoControl(m_hDriver, Ioctl, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, &dwReturned, NULL);

	if (BytesReturned)
		*BytesReturned = dwReturned;
	return bStatus;
}

bool CDeviceHelper::SendCryptedIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned)
{
	// Sanity check
	if (!InputBuffer || !InputBufferSize || !OutputBuffer || !OutputBufferSize)
	{
		printf("Sanity failed!");
		return false;
	}

	// Allocate memory for store crypted buffer
	const auto lpCryptedBuffer = malloc(InputBufferSize + 4); // Input Buffer size + Magic header size
	if (!lpCryptedBuffer)
	{
		printf("Memory allocation failed. Last error: %lu", GetLastError());
		return false;
	}
		
	// Place magic header to crypted memory buffer
	const auto pCryptedBufferMagic = NM_IOCTL_MAGIC;
	memcpy(lpCryptedBuffer, &pCryptedBufferMagic, 4);

	// Copy RAW memory to crypted memory buffer
	memcpy((void*)((LPBYTE)lpCryptedBuffer + 4), InputBuffer, InputBufferSize); // Skip first 4 byte(reserved for magic)

	// Encrypt memory
	__EncryptBuffer((uint8_t*)((LPBYTE)lpCryptedBuffer + 4), InputBufferSize, 0x69);

	// Send
	const auto bRet = SendRawIOCTL(Ioctl, lpCryptedBuffer, InputBufferSize + 4, OutputBuffer, OutputBufferSize, BytesReturned);

	// Free allocated crypter memory buffer
	free(lpCryptedBuffer);

	// Complete
	return bRet;
}

bool CDeviceHelper::SendIOCTL(DWORD Ioctl, PVOID InputBuffer, ULONG InputBufferSize, PVOID OutputBuffer, ULONG OutputBufferSize, PDWORD BytesReturned, DWORD Method)
{
	const auto dwRawIoctl = CTL_CODE(0x8000, Ioctl, Method, FILE_ANY_ACCESS);
	return SendCryptedIOCTL(dwRawIoctl, InputBuffer, InputBufferSize, OutputBuffer, OutputBufferSize, BytesReturned);
}

bool CDeviceHelper::SendRequest(DWORD dwIndex, IN PVOID pInput, ULONG ulInputSize, OUT PVOID pOutput, ULONG ulOutputSize)
{
	return SendIOCTL(CTL_BASE + dwIndex, pInput, ulInputSize, pOutput, ulOutputSize);
}
