#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "HotPatch.hpp"
#include "Hooks.hpp"

#if 0
NoMercy::NtDirect* ntd_NtProtectVirtualMemory = nullptr;

// NOTE: These use __cdecl because we don't want to have to adjust the stack coming back from this.
typedef NTSTATUS(__cdecl* pNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);


static NTSTATUS NTAPI hk_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection) {
	OutputDebugStringA("In Our Hooked NtProtectVirtualMemory");
	pNtProtectVirtualMemory ofn = reinterpret_cast<pNtProtectVirtualMemory>(ntd_NtProtectVirtualMemory->get_ptr());
	return ofn(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

auto hookret = this->SelfHooksInstance()->SyscallHook("NtProtectVirtualMemory", 0, &hk_NtProtectVirtualMemory, ntd_NtProtectVirtualMemory);
#endif

namespace NoMercy
{
	bool CSelfApiHooks::SyscallHook(const std::string& name, const uint32_t id, void* dest, NoMercy::NtDirect*& ref_ptr)
	{
		APP_TRACE_LOG(LL_SYS, L"SyscallHook: %s, %u", name.c_str(), id);

		if (name.empty() && id == 0)
			return false;

		auto bRet = false;
		NtDirect* api = nullptr;
		HotPatch* hp = nullptr;

		do
		{
			api = new (std::nothrow) NtDirect(id, name.c_str());
			if (!api)
			{
				APP_TRACE_LOG(LL_ERR, L"NtDirect create failed!");
				break;
			}
			ref_ptr = api;

			if (!api->load())
			{
				APP_TRACE_LOG(LL_ERR, L"NtDirect load failed!");
				break;
			}

			APP_TRACE_LOG(LL_SYS, L"HotPatching...");

			hp = new (std::nothrow) HotPatch(g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, name.c_str()));
			if (!hp)
			{
				APP_TRACE_LOG(LL_ERR, L"HotPatch create failed!");
				break;
			}

			if (!hp->patch(dest))
			{
				APP_TRACE_LOG(LL_ERR, L"HotPatch patch failed!");
				break;
			}

			m_vecSyscallHookedFuncs.push_back(std::make_tuple(name, api, hp));
			bRet = true;
		} while (false);

		if (!bRet)
		{
			if (api)
			{
				api->clear();
				
				delete api;
				api = nullptr;
			}
			
			if (hp)
			{
				hp->unpatch();
				
				delete hp;
				hp = nullptr;
			}
			
			ref_ptr = nullptr;
		}
		
		return bRet;
	}

	bool CSelfApiHooks::RemoveSyscallHook(const std::string& target)
	{
		APP_TRACE_LOG(LL_SYS, L"RemoveHookFn: %s", target.c_str());

		for (auto& t : m_vecSyscallHookedFuncs)
		{
			auto& [name, api, hp] = t;
			if (!api || !hp)
				continue;

			if (name == target)
			{
				api->clear();
				hp->unpatch();

				delete api;
				delete hp;

				m_vecSyscallHookedFuncs.erase(std::remove(m_vecSyscallHookedFuncs.begin(), m_vecSyscallHookedFuncs.end(), t), m_vecSyscallHookedFuncs.end());
				return true;
			}
		}

		return false;
	}

	bool CSelfApiHooks::RemoveSyscallHooks()
	{
		APP_TRACE_LOG(LL_SYS, L"RemoveAllHooks");

		for (auto& t : m_vecSyscallHookedFuncs)
		{
			auto& [name, api, hp] = t;
			if (!api || !hp)
				continue;

			api->clear();
			hp->unpatch();

			delete api;
			delete hp;
		}

		m_vecSyscallHookedFuncs.clear();
		return true;
	}
};
