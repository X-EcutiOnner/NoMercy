#include "../include/Index.hpp"
#include "../include/TLS.hpp"

namespace NoMercyTLS
{
	void NTAPI CTLSIndex::TlsRedirector(PVOID hModule, DWORD dwReason, PVOID pContext)
	{
		TLS_Routine(hModule, dwReason, pContext);
	}
}
