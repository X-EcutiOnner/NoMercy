#pragma once

namespace NoMercy
{
	class HotPatch
	{
	public:
		HotPatch(void* target);
		~HotPatch();
		
		bool patch(void* dest_fptr);
		bool unpatch(void);
		
	private:
		void* m_patched_address;
		void* m_hotpatch_fptr;
		size_t m_backup_length;
		uint8_t m_backup_bytes[16];
	};

	class NtDirect
	{
	public:
		NtDirect(uint32_t service_id, const std::string& service_name);
		~NtDirect();
		
		bool load();
		void clear();

		auto get_ptr() { return m_ptr; };

	protected:
		uint32_t get_service_id();
		
	private:
		uint8_t			m_syscall_stub_size;
		uint8_t*		m_syscall_stub;
		uint32_t		m_service_id;
		std::string	m_service_name;
		void*			m_ptr;
	};
}
