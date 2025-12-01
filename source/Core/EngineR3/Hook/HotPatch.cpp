#include "../PCH.hpp"
#include "HotPatch.hpp"

#define PAGE_SIZE 0x1000

#ifdef _WIN64
static constexpr auto HOTPATCH_ADDRESS_OFFSET = 2;
static uint8_t hotpatch_stub[] = {
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rax, [Abs Jump Address]
	0xFF, 0xE0,													// jmp rax
	0xC3,														// ret
};
#else
static constexpr auto HOTPATCH_ADDRESS_OFFSET = 1;
static uint8_t hotpatch_stub[] = {
	0xB8, 0x00, 0x00, 0x00, 0x00,								// mov eax, [Abs Jump Address]
	0xFF, 0xE0,													// jmp eax
	0xC3														// ret
};
#endif

namespace NoMercy
{
	HotPatch::HotPatch(void* target) :
		m_patched_address(target)
	{
		m_hotpatch_fptr = nullptr;
		m_backup_length = 0;
		RtlZeroMemory(m_backup_bytes, sizeof(m_backup_bytes));
	}
	HotPatch::~HotPatch()
	{
		this->unpatch();
		
		m_hotpatch_fptr = nullptr;
		m_backup_length = 0;
		m_patched_address = nullptr;
		RtlZeroMemory(m_backup_bytes, sizeof(m_backup_bytes));
	}
	
	bool HotPatch::patch(void* dest_fptr)
	{
		if (!m_patched_address || m_hotpatch_fptr)
			return false;
		
		unsigned char stub_code[sizeof(hotpatch_stub)]{ 0x0 };
		memcpy(stub_code, hotpatch_stub, sizeof(hotpatch_stub));
		memcpy(stub_code + HOTPATCH_ADDRESS_OFFSET, &dest_fptr, sizeof(DWORD_PTR));

		// Copy the stub code
		LPVOID target_addr = m_patched_address;
		DWORD dwOldProtect = 0;
		size_t stub_size = sizeof(stub_code);
		if (!g_winAPIs->VirtualProtect(target_addr, stub_size, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualProtect(pre) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		
		memcpy(m_backup_bytes, target_addr, stub_size);
		m_backup_length = stub_size;
		memcpy(target_addr, stub_code, stub_size);
		
		if (!g_winAPIs->VirtualProtect(target_addr, stub_size, dwOldProtect, &dwOldProtect))
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualProtect(post) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		
		m_hotpatch_fptr = dest_fptr;
		return true;
	}

	bool HotPatch::unpatch()
	{
		if (!m_patched_address || !m_hotpatch_fptr)
			return false;

		DWORD dwOldProtect = 0;
		if (!g_winAPIs->VirtualProtect((LPVOID)m_patched_address, m_backup_length, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualProtect(pre) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}
		
		memcpy((LPVOID)m_patched_address, m_backup_bytes, m_backup_length);
		g_winAPIs->VirtualProtect((LPVOID)m_patched_address, m_backup_length, dwOldProtect, &dwOldProtect);
		return true;
	}


	LPVOID allocate_exec_page()
	{
		return g_winAPIs->VirtualAlloc(nullptr, PAGE_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}

	void clear_exec_page(LPVOID addr)
	{
		DWORD dwOldProtect = 0;
		if (g_winAPIs->VirtualProtect((LPVOID)addr, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			RtlZeroMemory(addr, PAGE_SIZE);
			g_winAPIs->VirtualProtect((LPVOID)addr, PAGE_SIZE, dwOldProtect, &dwOldProtect);

			g_winAPIs->VirtualFree(addr, 0, MEM_RELEASE);
		}
	}

	NtDirect::NtDirect(uint32_t service_id, const std::string& service_name) :
		m_service_id(service_id), m_service_name(service_name)
	{
		m_ptr = nullptr;

#ifdef _WIN64
		// Syscall template for 64 bit Processes on a 64 bit OS.
		uint8_t syscall_stub[] = {
			0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, [SERVICE_ID]
			0x4C, 0x8B, 0xD1,             // mov r10, rcx
			0x0F, 0x05,                   // syscall
			0xC3                          // ret
		};
		m_syscall_stub_size = sizeof(syscall_stub);
		m_syscall_stub = new  uint8_t[m_syscall_stub_size];
		memcpy(m_syscall_stub, syscall_stub, m_syscall_stub_size);
#else
		if (stdext::is_wow64())
		{
			uint8_t syscall_stub[] = {
				0xB8, 0x00, 0x00, 0x00, 0x00,				// mov eax, [SERVICE_ID]
				0x64, 0xFF, 0x15, 0xC0, 0x00, 0x00, 0x00,	// call dword ptr fs : [0xC0] -- wow64cpu!X86SwitchTo64BitMode
				0xC3
			};			
			
			m_syscall_stub_size = sizeof(syscall_stub);
			m_syscall_stub = new uint8_t[m_syscall_stub_size];
			memcpy(m_syscall_stub, syscall_stub, m_syscall_stub_size);
		}
		else
		{
			uint8_t syscall_stub[] = {
				0xB8, 0x00, 0x00, 0x00, 0x00,				// mov eax, [SERVICE_ID]
				0xBA, 0x00, 0x03, 0xFE, 0x7F,				// mov edx, offset SharedUserData!SystemCallStub
				0xFF, 0x12,									// call dword ptr [edx]
				0xC3
			};

			m_syscall_stub_size = sizeof(syscall_stub);
			m_syscall_stub = new uint8_t[m_syscall_stub_size];
			memcpy(m_syscall_stub, syscall_stub, m_syscall_stub_size);
		}
#endif
	}
	NtDirect::~NtDirect()
	{
		m_ptr = nullptr;

		if (m_syscall_stub)
		{
			delete[] m_syscall_stub;
			m_syscall_stub = nullptr;
		}
	}

	bool NtDirect::load()
	{
		auto id = m_service_id;
		if (!m_service_name.empty())
			id = this->get_service_id();

		if (!id)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get service ID for %s", m_service_name.c_str());
			return false;
		}

		auto exec_page = allocate_exec_page();
		if (!exec_page)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to allocate exec page");
			return false;
		}

		*(unsigned int*)(m_syscall_stub + 1) = id;

		DWORD dwOldProtect = 0;
		if (!g_winAPIs->VirtualProtect((LPVOID)exec_page, PAGE_SIZE, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		{
			APP_TRACE_LOG(LL_ERR, L"VirtualProtect(pre) failed with error: %u", g_winAPIs->GetLastError());
			return false;
		}

		memcpy(exec_page, m_syscall_stub, m_syscall_stub_size);
		g_winAPIs->VirtualProtect((LPVOID)exec_page, PAGE_SIZE, dwOldProtect, &dwOldProtect);
		
		m_ptr = exec_page;
		return true;
	}
	void NtDirect::clear()
	{
		if (m_ptr)
		{
			clear_exec_page(m_ptr);
			m_ptr = nullptr;
		}
	}

	uint32_t NtDirect::get_service_id()
	{
		uint32_t service_id = 0;
		
		const auto faddr = g_winAPIs->GetProcAddress_o(g_winModules->hNtdll, m_service_name.c_str());
		if (!faddr)
		{
			APP_TRACE_LOG(LL_ERR, L"Failed to get address of %s with error: %u", m_service_name.c_str(), g_winAPIs->GetLastError());
			return service_id;
		}

		unsigned char pchk[8]{ 0x00 };
		memcpy(pchk, faddr, sizeof(pchk));
		
		for (int i = 0; i < sizeof(pchk); i++)
		{
			if (pchk[i] == 0xB8)
			{
				memcpy(&service_id, pchk + i + 1, sizeof(unsigned int));
			}
		}
		
		RtlZeroMemory(pchk, sizeof(pchk));
		return service_id;
	}
}
