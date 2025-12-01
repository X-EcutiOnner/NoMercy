#pragma once
#include <dia2.h>

namespace NoMercy
{
	class PdbHelper
	{
	public:
		PdbHelper();
		~PdbHelper();

		bool init(const std::wstring& filepath, const std::wstring& local_cache_path);

		std::optional <uint32_t> symbol_address(const std::wstring& symbol_name)
		{
			if (auto it = m_cache.find(symbol_name); it != m_cache.end())
			{
				return it->second;
			}
			return std::nullopt;
		}

	protected:
		IDiaDataSource* create_ida_source();
		bool populate_symbols();

		// make the compiler happy
		static std::wstring make_symbol_path(const std::wstring& local_cache_path) noexcept
		{
			return fmt::format(xorstr_(L"srv*{0}*https://msdl.microsoft.com/download/symbols"), local_cache_path);
		}

		// make the compiler happy
		static auto make_DllGetClassObject() noexcept
		{
			return xorstr_("DllGetClassObject");
		}

	private:
		IDiaDataSource* m_source;
		IDiaSession* m_session;
		IDiaSymbol* m_global;

		std::unordered_map <std::wstring, uint32_t> m_cache;      // Symbol name <--> RVA map
	};
}