#include "../../include/PCH.hpp"
#include "../../include/Smbios.hpp"
#include "../../include/MemAllocator.hpp"
#include "../../include/SafeExecutor.hpp"

namespace NoMercyCore
{
	CSmbiosParser::CSmbiosParser() :
		m_smbios_version(0)
	{
	}
	CSmbiosParser::~CSmbiosParser()
	{
	}

	void CSmbiosParser::enum_tables(TEnumFn enum_fn)
	{
		for (auto table_entries : m_tables)
		{
			for (auto type_table : table_entries.second)
			{
				enum_fn(table_entries.first, type_table.handle);
			}
		}
	}

	bool CSmbiosParser::parse()
	{
		const auto upExecutor = std::make_unique<CSafeExecutor>(false);
		if (IS_VALID_SMART_PTR(upExecutor))
		{
			TSafeExecutorDefaultHandler __ParseImplFunc = [&]() {
				const auto table_size = g_winAPIs->GetSystemFirmwareTable('RSMB', 0, nullptr, 0);
				if (!table_size)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to get SMBIOS table size");
					return false;
				}

				const auto buffer = CMemHelper::Allocate(table_size);
				if (!buffer)
				{
					APP_TRACE_LOG(LL_ERR, L"Failed to allocate buffer");
					return false;
				}

				if (g_winAPIs->GetSystemFirmwareTable('RSMB', 0, buffer, table_size) != table_size)
				{
					APP_TRACE_LOG(LL_ERR, L"GetSystemFirmwareTable failed with error: %u", g_winAPIs->GetLastError());
					CMemHelper::Free(buffer);
					return false;
				}
				const auto smbios = reinterpret_cast<smbios_t*>(buffer);

				__save_smbios_version(smbios);

				if (smbios->length <= sizeof(smbios_t))
				{
					APP_TRACE_LOG(LL_ERR, L"SMBIOS table has no entries");
					CMemHelper::Free(buffer);
					return false;
				}

				// First table
				detail::entry_handle handle = 0;
				auto table_header = reinterpret_cast<table_header_t*>(std::uintptr_t(buffer) + sizeof(smbios_t));
				do
				{
					std::uint8_t* string_table = reinterpret_cast<std::uint8_t*>(std::uintptr_t(table_header) + table_header->length);

					// Parse string table
					detail::table_string_container table_strings = { };
					auto string_table_size = __parse_string_table(string_table, table_strings);

					// Add the table into our parsed tables
					// Some tables have multiple entries, which is why we use a container
					m_tables[table_header->type].emplace_back(table_header, handle, table_strings);

					// Go to next entry
					table_header = reinterpret_cast<table_header_t*>(string_table + string_table_size);

					// Increase the handle
					handle++;
				} while (table_header->type != (std::uint8_t)smbios_table_types::end_of_table || table_header->length != 4);

				CMemHelper::Free(buffer);
				return true;
			};

			const auto spRet = upExecutor->SafeExec<bool>(SAFE_FUNCTION_ID_SMBIOS_PARSE, __ParseImplFunc);
			APP_TRACE_LOG(LL_SYS, L"Smbios parser safe execution completed. Ptr: %p, Error code: %u, Return code: %d, Return value: 0x%lld, Exception message: %s",
				spRet ? spRet.get() : nullptr,
				IS_VALID_SMART_PTR(spRet) ? spRet->error_code : 0,
				IS_VALID_SMART_PTR(spRet) ? spRet->return_code : 0,
				IS_VALID_SMART_PTR(spRet) ? spRet->return_value.has_value() ? spRet->return_value.value() : 0ll : 0,
				IS_VALID_SMART_PTR(spRet) ? spRet->error_message.c_str() : xorstr_("N/A")
			);

			if (IS_VALID_SMART_PTR(spRet) && spRet->error_code && IS_VALID_SMART_PTR(spRet->exception))
			{
				APP_TRACE_LOG(LL_CRI, L"Safe executor Exception detected. Address: %p (%s) Code: %p Flags: %u",
					spRet->exception->address, spRet->exception->address_symbol, spRet->exception->code, spRet->exception->flags
				);

				APP_TRACE_LOG(LL_SYS, L"Registers:");
				for (const auto& [reg, val] : spRet->exception->registers)
				{
					APP_TRACE_LOG(LL_SYS, L"%s: %p", reg.c_str(), val);
				}

				APP_TRACE_LOG(LL_SYS, L"Stack:");
				for (const auto& ctx : spRet->exception->stack)
				{
					if (IS_VALID_SMART_PTR(ctx))
					{
						APP_TRACE_LOG(LL_SYS, L"[%llu] %p Module: %s Image: %s Symbol: %s File: %s (%u)", ctx->idx, ctx->frame, ctx->module_name, ctx->image_name, ctx->symbol_name, ctx->file_name, ctx->file_line);
					}
				}
			}

			if (!IS_VALID_SMART_PTR(spRet) || spRet->error_code || spRet->return_code || !spRet->return_value || !spRet->error_message.empty())
			{
				APP_TRACE_LOG(LL_ERR, L"Failed to parse SMBIOS table");
				return false;
			}
		}

		return true;
	}

	void CSmbiosParser::__save_smbios_version(smbios_t* smbios)
	{
		char version_string[8]{ '\0' };
		snprintf(version_string, std::size(version_string), xorstr_("%d.%d"), smbios->major_version, smbios->minor_verion);

		m_smbios_version = std::stod(version_string);
	}

	std::uint8_t CSmbiosParser::__parse_string_table(std::uint8_t* string_table, detail::table_string_container& out)
	{
		std::uint8_t size = 0, string_count = 1;

		for (; ; size++, string_table++)
		{
			if (*string_table)
				out[string_count].push_back(*string_table);
			else // String end is marked with a null byte
				string_count++;

			// End of structure is marked by 2x null bytes (end-of-string + additional null terminator)
			if ((*string_table | *(string_table + 1)) == 0)
				break;
		}

		return size + 2; // Account for the 2 extra bytes
	}
}
