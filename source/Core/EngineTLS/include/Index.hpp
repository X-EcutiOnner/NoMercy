#pragma once

namespace NoMercyTLS
{
	class CTLSIndex
	{
	public:
		static void NTAPI TlsRedirector(PVOID hModule, DWORD dwReason, PVOID pContext);
	};
};
