#pragma once
#include "Smbios_data.hpp"

namespace NoMercyCore
{
	class CSmbiosParser
	{
		using TEnumFn = std::function<void(std::uint8_t table_type, detail::entry_handle entry_handle)>;

	public:
		CSmbiosParser();
		~CSmbiosParser();

		bool parse();

		auto get_version() const { return m_smbios_version; };
		void enum_tables(TEnumFn enum_fn);

		template <typename T>
		detail::smbios_table <T> get_table_by_handle(detail::entry_handle handle)
		{
			for (auto& table_type : m_tables)
			{
				for (auto& table_entry : table_type.second)
				{
					if (table_entry.handle == handle)
						return detail::smbios_table<T>(table_entry);
				}
			}

			return {};
		}

	protected:
		void __save_smbios_version(smbios_t* smbios);

		std::uint8_t __parse_string_table(std::uint8_t* string_table, detail::table_string_container& out);

	private:
		double m_smbios_version;
		std::unordered_map <std::uint8_t, std::vector <detail::smbios_table_entry_t> > m_tables;
	};
};
