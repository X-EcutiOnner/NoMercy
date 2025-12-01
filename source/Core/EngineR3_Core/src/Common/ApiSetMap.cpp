#include "../../include/PCH.hpp"
#include "../../include/ApiSetMap.hpp"
#include "../../include/WinAPIManager.hpp"

namespace ApiSetMap
{
	class V2V4ApiSetSchema final : public ApiSetSchemaBase
	{
	public:
		std::vector <std::pair <std::wstring, ApiSetTarget>> All;

		std::vector <std::pair <std::wstring, ApiSetTarget>> GetAll() override
		{
			return All;
		}
		
		ApiSetTarget Lookup(std::wstring name) override
		{
			// Force lowercase name
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);

			// Remove extension from name
			const auto pos = name.find_last_of(L'.');
			if (pos != std::wstring::npos)
				name.erase(pos);

			// Remove "api-" or "ext-" prefix
			if (name.compare(0, 4, xorstr_(L"api-")) == 0)
				name.erase(0, 4);
			else if (name.compare(0, 4, xorstr_(L"ext-")) == 0)
				name.erase(0, 4);

			// Lookup in hashed table
			for (const auto& pair : All)
			{
				if (pair.first == name)
					return pair.second;
			}

			// Not found, return empty target
			return ApiSetTarget();
		}
	};

	std::unique_ptr <ApiSetSchemaBase> ApiSetSchemaImpl::ParseApiSetSchema(const API_SET_NAMESPACE_UNION* apiSetMap)
	{
		// Check the returned api namespace is correct
		if (!apiSetMap)
			return std::unique_ptr<ApiSetSchemaBase>(new (std::nothrow) EmptyApiSetSchema());

		switch (apiSetMap->Version)
		{
		case 2: // Win7
			return GetApiSetSchemaV2(&(apiSetMap->ApiSetNameSpaceV2));

		case 4: // Win8.1
			return GetApiSetSchemaV4(&(apiSetMap->ApiSetNameSpaceV4));

		case 6: // Win10
			return GetApiSetSchemaV6(&(apiSetMap->ApiSetNameSpaceV6));

		default: // unsupported
			return std::unique_ptr<ApiSetSchemaBase>(new (std::nothrow) EmptyApiSetSchema());
		}
	}

	std::unique_ptr <ApiSetSchemaBase> ApiSetSchemaImpl::GetApiSetSchemaV2(const API_SET_NAMESPACE_V2* map)
	{
		const auto base = reinterpret_cast<ULONG_PTR>(map);
		auto schema = std::unique_ptr <V2V4ApiSetSchema>(new V2V4ApiSetSchema());
		for (auto it = map->Array, eit = it + map->Count; it < eit; ++it)
		{
			// Retrieve DLLs names implementing the contract
			ApiSetTarget targets;
			const auto value_entry = reinterpret_cast<PAPI_SET_VALUE_ENTRY_V2>(base + it->DataOffset);
			for (auto it2 = value_entry->Redirections, eit2 = it2 + value_entry->NumberOfRedirections; it2 < eit2; ++it2)
			{
				const auto value_buffer = reinterpret_cast<PWCHAR>(base + it2->ValueOffset);
				const auto value = std::wstring(value_buffer, 0, it2->ValueLength / sizeof(WCHAR));
				targets.push_back(value);
			}

			// Retrieve api min-win contract name
			const auto name_buffer = reinterpret_cast<PWCHAR>(base + it->NameOffset);
			auto name = std::wstring(name_buffer, 0, it->NameLength / sizeof(WCHAR));

			// force storing lowercase variant for comparison
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);
			std::wstring lower_name = std::move(name);

			schema->All.push_back(make_pair(lower_name, targets));
		}
		return schema;
	}

	std::unique_ptr <ApiSetSchemaBase> ApiSetSchemaImpl::GetApiSetSchemaV4(const API_SET_NAMESPACE_V4* map)
	{
		const auto base = reinterpret_cast<ULONG_PTR>(map);
		auto schema = std::unique_ptr <V2V4ApiSetSchema>(new V2V4ApiSetSchema());
		for (auto it = map->Array, eit = it + map->Count; it < eit; ++it)
		{
			// Retrieve DLLs names implementing the contract
			auto targets = ApiSetTarget();
			const auto value_entry = reinterpret_cast<PAPI_SET_VALUE_ENTRY_V4>(base + it->DataOffset);
			for (auto it2 = value_entry->Redirections, eit2 = it2 + value_entry->NumberOfRedirections; it2 < eit2; ++it2)
			{
				const auto value_buffer = reinterpret_cast<PWCHAR>(base + it2->ValueOffset);
				const auto value = std::wstring(value_buffer, 0, it2->ValueLength / sizeof(WCHAR));
				targets.push_back(value);
			}

			// Retrieve api min-win contract name
			const auto name_buffer = reinterpret_cast<PWCHAR>(base + it->NameOffset);
			auto name = std::wstring(name_buffer, 0, it->NameLength / sizeof(WCHAR));

			// force storing lowercase variant for comparison
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);
			const auto lower_name = std::move(name);

			schema->All.push_back(make_pair(lower_name, targets));
		}
		return schema;
	}

	class V6ApiSetSchema sealed : public ApiSetSchemaBase
	{
	public:
		std::vector <std::pair <std::wstring, ApiSetTarget>> All = std::vector <std::pair <std::wstring, ApiSetTarget>>();
		std::vector <std::pair <std::wstring, ApiSetTarget>> HashedAll = std::vector <std::pair <std::wstring, ApiSetTarget>>();

		std::vector <std::pair <std::wstring, ApiSetTarget>> GetAll() override
		{
			return All;
		}
		
		ApiSetTarget Lookup(std::wstring name) override
		{
			// Force lowercase name
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);

			// Remove extension from name
			const auto pos = name.find_last_of(L'.');
			if (pos != std::wstring::npos)
				name.erase(pos);

			// Lookup in hashed table
			for (const auto& pair : All)
			{
				if (pair.first == name)
					return pair.second;
			}

			// Not found, return empty target
			return ApiSetTarget();
		}
	};

	std::unique_ptr <ApiSetSchemaBase> ApiSetSchemaImpl::GetApiSetSchemaV6(const API_SET_NAMESPACE_V6* map)
	{
		const auto base = reinterpret_cast<ULONG_PTR>(map);
		auto schema = std::unique_ptr<V6ApiSetSchema>(new V6ApiSetSchema());
		for (auto it = reinterpret_cast<PAPI_SET_NAMESPACE_ENTRY_V6>(map->EntryOffset + base), eit = it + map->Count; it < eit; ++it)
		{
			// Iterate over all the host dll for this contract
			auto targets = ApiSetTarget();
			for (auto it2 = static_cast<_API_SET_VALUE_ENTRY_V6* const>(reinterpret_cast<PAPI_SET_VALUE_ENTRY_V6>(base + it->ValueOffset)), eit2 = it2 + it->ValueCount; it2 < eit2; ++it2)
			{
				// Retrieve DLLs name implementing the contract
				const auto value_buffer = reinterpret_cast<PWCHAR>(base + it2->ValueOffset);
				const auto value = std::wstring(value_buffer, 0, it2->ValueLength / sizeof(WCHAR));
				targets.push_back(value);
			}

			// Retrieve api min-win contract name
			const auto name_buffer = reinterpret_cast<PWCHAR>(base + it->NameOffset);
			auto name = std::wstring(name_buffer, 0, it->NameLength / sizeof(WCHAR));
			auto hash_name = std::wstring(name_buffer, 0, it->HashedLength / sizeof(WCHAR));

			// force storing lowercase variant for comparison
			std::transform(name.begin(), name.end(), name.begin(), ::tolower);
			const auto lower_name = std::move(name);
			std::transform(hash_name.begin(), hash_name.end(), hash_name.begin(), ::tolower);
			const auto lower_hash_name = std::move(name);

			schema->All.push_back(make_pair(lower_name, targets));
			schema->HashedAll.push_back(make_pair(lower_hash_name, targets));
		}
		return schema;
	}

	PAPI_SET_NAMESPACE_UNION GetApiSetNamespace()
	{
		auto peb = NtCurrentPeb();
		if (peb)
			return (PAPI_SET_NAMESPACE_UNION)((PVOID)(peb->ApiSetMap));
		return nullptr;
	}
};
