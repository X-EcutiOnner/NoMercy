#include "../../include/PCH.hpp"
#include "../../include/Screenshot.hpp"
#include "../../include/WinVerHelper.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../../../Common/FilePtr.hpp"

#include <shlwapi.h>
#pragma warning(push) 
#pragma warning(disable: 4458)
#include <GdiPlus.h>
#pragma warning(pop) 

namespace NoMercyCore
{
	CScreenshotMgr::CScreenshotMgr()
	{
	}
	CScreenshotMgr::~CScreenshotMgr()
	{
	}

	int GetEncoderClsid(const WCHAR* format, CLSID* pClsid)
	{
		UINT uiNum = 0, uiSize = 0;
		Gdiplus::GetImageEncodersSize(&uiNum, &uiSize);
		if (uiSize == 0)
			return -2; // Failure

		const auto pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(uiSize));
		if (!pImageCodecInfo)
			return -3; // Failure

		if (Gdiplus::GetImageEncoders(uiNum, uiSize, pImageCodecInfo) != Gdiplus::Status::Ok)
		{
			free(pImageCodecInfo);
			return -4; // Failure
		}

		for (UINT i = 0; i < uiNum; ++i)
		{
			if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0)
			{
				*pClsid = pImageCodecInfo[i].Clsid;
				free(pImageCodecInfo);
				return i; // Success
			}
		}

		free(pImageCodecInfo);
		return -1; // Failure
	}

	static bool __CaptureScreenshot(HDC hdcMonitor, LPRECT lprcMonitor)
	{
		const auto idx = CApplication::Instance().ScreenshotManagerInstance()->GetScreenshotSize() + 1;
		APP_TRACE_LOG(LL_SYS, L"Creating screenshot: %u", idx);

		auto bRet = false;
		HANDLE hDIB = INVALID_HANDLE_VALUE;
		HBITMAP hbmScreen = nullptr;
		HDC hdcMemDC = nullptr;
		IStream* stream = nullptr;
		ULONG_PTR gdiplusToken = 0;

		do
		{
			DWORD dwQuality = 85;
			Gdiplus::Status status = Gdiplus::Status::Ok;
			HRESULT stream_status = S_OK;
			BITMAPINFOHEADER bi{ 0 };
			PVOID pBufferJpg = nullptr;
			DWORD dwBufferSize = 0;
			CLSID jpgClsid{ 0 };
			Gdiplus::EncoderParameters encoderParameters{ 0 };
			int result = 0;
			Gdiplus::Bitmap* pBmpData = nullptr;
			BITMAP bmpScreen{ 0 };
			RECT rcClient{ 0 };
			Gdiplus::GdiplusStartupInput gdiplusStartupInput{ 0 };
			STATSTG ss{ 0 };
			LARGE_INTEGER streamStart = {};
			ULARGE_INTEGER streamPos = {};

			/// GDI+ Init
			status = Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
			if (status != Gdiplus::Status::Ok)
			{
				APP_TRACE_LOG(LL_ERR, L"GdiplusStartup fail! Error: %u", status);
				break;
			}

			// Create a compatible DC which is used in a BitBlt from the window DC
			hdcMemDC = g_winAPIs->CreateCompatibleDC(hdcMonitor);
			if (!hdcMemDC)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateCompatibleDC fail. Error code: %u", g_winAPIs->GetLastError());
				break;
			}

			// Get the client area for size calculation
			rcClient = *lprcMonitor;

			// Create a compatible bitmap from the Window DC
			hbmScreen = g_winAPIs->CreateCompatibleBitmap(hdcMonitor, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top);
			if (!hbmScreen)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateCompatibleBitmap fail. Error code: %u", g_winAPIs->GetLastError());
				break;
			}

			// Select the compatible bitmap into the compatible memory DC.
			g_winAPIs->SelectObject(hdcMemDC, hbmScreen);

			// Bit block transfer into our compatible memory DC.
			if (!g_winAPIs->BitBlt(hdcMemDC, 0, 0, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, hdcMonitor, lprcMonitor->left, lprcMonitor->top, SRCCOPY))
//			if (!g_winAPIs->BitBlt(hdcMemDC, 0, 0, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, hdcMonitor, 0, 0, SRCCOPY))
			{
				APP_TRACE_LOG(LL_ERR, L"BitBlt fail. Error code: %u", g_winAPIs->GetLastError());
				break;
			}

			// Get the BITMAP from the HBITMAP
			g_winAPIs->GetObjectW(hbmScreen, sizeof(BITMAP), &bmpScreen);

			bi.biSize = sizeof(BITMAPINFOHEADER);
			bi.biWidth = bmpScreen.bmWidth;
			bi.biHeight = bmpScreen.bmHeight;
			bi.biPlanes = 1;
			bi.biBitCount = 32;
			bi.biCompression = BI_RGB;
			bi.biSizeImage = 0;
			bi.biXPelsPerMeter = 0;
			bi.biYPelsPerMeter = 0;
			bi.biClrUsed = 0;
			bi.biClrImportant = 0;

			DWORD dwBmpSize = ((bmpScreen.bmWidth * bi.biBitCount + 31) / 32) * 4 * bmpScreen.bmHeight;

			// Starting with 32-bit Windows, GlobalAlloc and LocalAlloc are implemented as wrapper functions that
			// call HeapAlloc using a handle to the process default heap. Therefore, GlobalAlloc and LocalAlloc
			// have greater overhead than HeapAlloc.
			hDIB = g_winAPIs->GlobalAlloc(GHND, dwBmpSize);
			char* lpbitmap = (char*)g_winAPIs->GlobalLock(hDIB);

			// Gets the "bits" from the bitmap and copies them into a buffer
			// which is pointed to by lpbitmap.
			g_winAPIs->GetDIBits(hdcMonitor, hbmScreen, 0, (UINT)bmpScreen.bmHeight, lpbitmap, (BITMAPINFO*)&bi, DIB_RGB_COLORS);

			// Add the size of the headers to the size of the bitmap to get the total file size
			DWORD dwSizeofDIB = dwBmpSize + sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

			BITMAPFILEHEADER bmfHeader;

			//Offset to where the actual bitmap bits start.
			bmfHeader.bfOffBits = (DWORD)sizeof(BITMAPFILEHEADER) + (DWORD)sizeof(BITMAPINFOHEADER);

			//Size of the file
			bmfHeader.bfSize = dwSizeofDIB;

			//bfType must always be BM for Bitmaps
			bmfHeader.bfType = 0x4D42; //BM

			// Convert to jpg
			pBmpData = Gdiplus::Bitmap::FromHBITMAP(hbmScreen, NULL);
			if (!pBmpData)
			{
				APP_TRACE_LOG(LL_ERR, L"Gdiplus::Bitmap::FromHBITMAP fail. Error code: %u", g_winAPIs->GetLastError());
				break;
			}
			encoderParameters.Count = 1;
			encoderParameters.Parameter[0].Guid = Gdiplus::EncoderQuality;
			encoderParameters.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
			encoderParameters.Parameter[0].NumberOfValues = 1;
			encoderParameters.Parameter[0].Value = &dwQuality;

			const std::wstring wstFormat = xorstr_(L"image/jpeg");
			result = GetEncoderClsid(wstFormat.c_str(), &jpgClsid);
			if (result < 0)
			{
				APP_TRACE_LOG(LL_ERR, L"GetEncoderClsidP fail. Error code: %u", g_winAPIs->GetLastError());
				break;
			}

			stream_status = g_winAPIs->CreateStreamOnHGlobal(nullptr, TRUE, &stream);
			if (!SUCCEEDED(stream_status))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateStreamOnHGlobal fail. Error code: %u", stream_status);
				break;
			}

			status = pBmpData->Save(stream, &jpgClsid, &encoderParameters);
			if (status != Gdiplus::Status::Ok)
			{
				APP_TRACE_LOG(LL_ERR, L"pBmpData->Save fail. Error code: %u", status);
				break;
			}

			// Get the beginning
			stream_status = stream->Seek(streamStart, STREAM_SEEK_SET, &streamPos);
			if (!SUCCEEDED(stream_status))
			{
				APP_TRACE_LOG(LL_ERR, L"stream->Seek fail. Error code: %u", stream_status);
				break;
			}

			if (stream->Stat(&ss, STATFLAG_NONAME) == S_OK && ss.cbSize.LowPart != 0)
			{
				dwBufferSize = ss.cbSize.LowPart;
				pBufferJpg = CMemHelper::Allocate(dwBufferSize);
				if (!pBufferJpg)
				{
					APP_TRACE_LOG(LL_ERR, L"Screenshot memory allocation2 fail. Error code: %u", g_winAPIs->GetLastError());
					break;
				}

				stream_status = stream->Read(pBufferJpg, dwBufferSize, &ss.cbSize.LowPart);
				if (stream_status != S_OK)
				{
					APP_TRACE_LOG(LL_ERR, L"stream->Read. Error code: %u Size: %u/%u", stream_status, dwBufferSize, ss.cbSize.LowPart);
					break;
				}

				CApplication::Instance().ScreenshotManagerInstance()->AppendScreenshot({ pBufferJpg, dwBufferSize });
				bRet = true;
			}
		} while (FALSE);

		// Unlock and Free the DIB from the heap
		if (hDIB)
		{
			g_winAPIs->GlobalUnlock(hDIB);
			g_winAPIs->GlobalFree(hDIB);
			hDIB = nullptr;
		}

		if (hbmScreen)
		{
			g_winAPIs->DeleteObject(hbmScreen);
			hbmScreen = nullptr;
		}
		if (hdcMemDC)
		{
			g_winAPIs->DeleteObject(hdcMemDC);
			hdcMemDC = nullptr;
		}

		if (stream)
		{
			stream->Release();
			stream = nullptr;
		}

		if (gdiplusToken)
		{
			Gdiplus::GdiplusShutdown(gdiplusToken);
			gdiplusToken = 0;
		}

		//if (pBmpData)
		//	delete pBmpData;

		return bRet;
	}

	BOOL CALLBACK OnMonitorEnum(HMONITOR, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM)
	{
		__CaptureScreenshot(hdcMonitor, lprcMonitor);
		return TRUE;
	}
	
	std::vector <SScreenshotData> CScreenshotMgr::CreateScreenshots()
	{
		// Clear latest buffer
		ClearScreenshotBuffer();

		// Enum monitors
		auto hDC = g_winAPIs->GetDC(nullptr);
		if (!hDC)
		{
			APP_TRACE_LOG(LL_ERR, L"GetDC fail! Error: %u", g_winAPIs->GetLastError());

			std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
			return m_vScreenshots;
		}
		
		if (!g_winAPIs->EnumDisplayMonitors(hDC, nullptr, OnMonitorEnum, 0))
		{
			APP_TRACE_LOG(LL_ERR, L"EnumDisplayMonitors fail! Error: %u", g_winAPIs->GetLastError());
		}
		
		g_winAPIs->ReleaseDC(nullptr, hDC);

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
		return m_vScreenshots;
	}
	void CScreenshotMgr::ClearScreenshotBuffer()
	{
		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);

		for (const auto& ss : m_vScreenshots)
		{
			if (ss.buffer)
			{
				CMemHelper::Free(ss.buffer);
			}
		}
		m_vScreenshots.clear();
	}
	void CScreenshotMgr::AppendScreenshot(const SScreenshotData& data)
	{
		APP_TRACE_LOG(LL_SYS, L"Created screenshot. ptr: %p size: %u", data.buffer, data.length);

		std::lock_guard <std::recursive_mutex> __lock(m_rmMutex);
		m_vScreenshots.emplace_back(data);
	}
}
