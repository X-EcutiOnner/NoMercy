#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "../Common/Quarentine.hpp"
#include "ScannerInterface.hpp"
#include "../Helper/PatternScanner.hpp"


namespace NoMercy
{
	static auto gs_dwDummy = (DWORD_PTR)0;
	static auto gs_bFailed = false;
	static auto gs_hRendererModule = (HMODULE)nullptr;
	static auto gs_spPatternScanner = std::unique_ptr<CPatternScanner>();

	inline void CheckHookOfVmtFunction(DWORD_PTR lpFunctionData, DWORD dwID)
	{
		uint8_t nHookType = 0;

		BYTE* pOpcode;
		const auto dwSize = SizeOfCode((void*)lpFunctionData, &pOpcode);

		if (*(BYTE*)lpFunctionData == 0xE9)
			nHookType = 1;

		else if(*(BYTE*)lpFunctionData == 0xE8)
			nHookType = 2;

		else if (*(WORD*)lpFunctionData == 0x25FF)
			nHookType = 3;

		if (nHookType)
		{
			APP_TRACE_LOG(LL_ERR, L"Hook (%u) detected on VMT function: %u (%p - %u)", nHookType, dwID, lpFunctionData, dwSize);
			// TODO: throw
		}

		return;
	}

	void ProtectDirectX12()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d12.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"DirectX12 renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectDirectX11()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d11.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"DirectX11 renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectDirectX10()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d10.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"DirectX10 renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}

	void ProtectDirectX9()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d9.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"DirectX9 renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		
		static const auto pattern = Pattern(xorstr_(L"C7 06 ? ? ? ? 89 86 ? ? ? ? 89 86"), PatternType::Address);
		static const auto lpD3DPattern = gs_spPatternScanner->findPatternSafe((LPVOID)gs_hRendererModule, 0x128000, pattern);
		if (!lpD3DPattern)
		{
			APP_TRACE_LOG(LL_ERR, L"DirectX9 base pattern could not detect vtable!");
			gs_bFailed = true;
			return;
		}

		DWORD_PTR* vTable = nullptr;

		SIZE_T cbReadSize = 0;
		if (!g_winAPIs->ReadProcessMemory(NtCurrentProcess(), (LPCVOID)((DWORD_PTR)lpD3DPattern + 2), &vTable, sizeof(vTable), &cbReadSize) ||
			cbReadSize != sizeof(vTable))
		{
			APP_TRACE_LOG(LL_ERR, L"DirectX9 vtable base could not read! Error: %u", g_winAPIs->GetLastError());
			gs_bFailed = true;
			return;
		}

		CheckHookOfVmtFunction((DWORD_PTR)vTable[41], 1); // BeginScene
		CheckHookOfVmtFunction((DWORD_PTR)vTable[42], 2); // EndScene
		CheckHookOfVmtFunction((DWORD_PTR)vTable[47], 3); // SetViewport
		CheckHookOfVmtFunction((DWORD_PTR)vTable[82], 4); // DrawIndexedPrimitive
		CheckHookOfVmtFunction((DWORD_PTR)vTable[100], 5); // SetStreamSource

		return;
	}
	void ProtectDirectX8()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d8.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"DirectX8 renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectVulcan()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"vulcan.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"Vulcan renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectOpenGL()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"opengl32.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"OpenGL renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectGDIPlus()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"gdiplus.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"GDI Plus renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}
	void ProtectGDI()
	{
		if (gs_bFailed)
			return;

		if (!gs_hRendererModule)
		{
			gs_hRendererModule = g_winAPIs->GetModuleHandleW_o(xorstr_(L"gdi32.dll"));
			if (!gs_hRendererModule)
			{
				APP_TRACE_LOG(LL_ERR, L"GDI renderer module could not found!");
				gs_bFailed = true;
				return;
			}
		}
		// NOT_IMPLEMENTED
	}

	void IScanner::CheckVTableIntegrity()
	{		
		if (gs_bFailed)
			return;

		if (!IS_VALID_SMART_PTR(gs_spPatternScanner))
		{
			gs_spPatternScanner = stdext::make_unique_nothrow<CPatternScanner>();
			if (!IS_VALID_SMART_PTR(gs_spPatternScanner))
			{
				APP_TRACE_LOG(LL_ERR, L"gs_spPatternScanner allocation fail");
				gs_bFailed = true;
				return;
			}
		}

		const auto renderer = CApplication::Instance().SDKHelperInstance()->GetRenderEngine();
		if (renderer.empty())
		{
			// If not set renderer by game sdk try detect from memory

			const auto directx12 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d12.dll"));
			const auto directx11 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d11.dll"));
			const auto directx10 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d10.dll"));
			const auto directx9 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d9.dll"));
			const auto directx8 = g_winAPIs->GetModuleHandleW_o(xorstr_(L"d3d8.dll"));
			const auto hVulcan = g_winAPIs->GetModuleHandleW_o(xorstr_(L"vulcan.dll"));
			const auto hOpengl = g_winAPIs->GetModuleHandleW_o(xorstr_(L"opengl32.dll"));
			const auto hGDIPlus = g_winAPIs->GetModuleHandleW_o(xorstr_(L"gdiplus.dll"));
			const auto hGDI = g_winAPIs->GetModuleHandleW_o(xorstr_(L"gdi32.dll"));

			if (directx12)
				ProtectDirectX12();
			else if (directx11)
				ProtectDirectX11();
			else if (directx10)
				ProtectDirectX10();
			else if (directx9)
				ProtectDirectX9();
			else if (directx8)
				ProtectDirectX8();
			else if (hVulcan)
				ProtectVulcan();
			else if (hOpengl)
				ProtectOpenGL();
			else if (hGDIPlus)
				ProtectGDIPlus();
			else if (hGDI)
				ProtectGDI();
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Render engine could not detected");
				gs_bFailed = true;
			}
		}
		else
		{
			if (renderer == xorstr_(L"directx12"))
				ProtectDirectX12();
			else if (renderer == xorstr_(L"directx11"))
				ProtectDirectX11();
			else if (renderer == xorstr_(L"directx10"))
				ProtectDirectX10();
			else if (renderer == xorstr_(L"directx9"))
				ProtectDirectX9();
			else if (renderer == xorstr_(L"directx8"))
				ProtectDirectX8();
			else if (renderer == xorstr_(L"vulcan"))
				ProtectVulcan();
			else if (renderer == xorstr_(L"opengl"))
				ProtectOpenGL();
			else if (renderer == xorstr_(L"gdiplus"))
				ProtectGDIPlus();
			else if (renderer == xorstr_(L"gdi"))
				ProtectGDI();
			else
			{
				APP_TRACE_LOG(LL_ERR, L"Unknown render engine: %s defined by game sdk", renderer.c_str());
				gs_bFailed = true;
			}
		}
	}
};
