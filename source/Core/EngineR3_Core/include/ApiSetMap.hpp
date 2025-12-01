#pragma once

namespace ApiSetMap
{
	///////////////////////////////////////////////////////////////////////////////
	// ApiSet v2

	typedef struct _API_SET_VALUE_ENTRY_REDIRECTION_V2 {
		ULONG  NameOffset;
		USHORT NameLength;
		ULONG  ValueOffset;
		USHORT ValueLength;
	} API_SET_VALUE_ENTRY_REDIRECTION_V2, * PAPI_SET_VALUE_ENTRY_REDIRECTION_V2;

	typedef struct _API_SET_VALUE_ENTRY_V2 {
		ULONG NumberOfRedirections;
		API_SET_VALUE_ENTRY_REDIRECTION_V2 Redirections[ANYSIZE_ARRAY];
	} API_SET_VALUE_ENTRY_V2, * PAPI_SET_VALUE_ENTRY_V2;

	typedef struct _API_SET_NAMESPACE_ENTRY_V2 {
		ULONG NameOffset;
		ULONG NameLength;
		ULONG DataOffset; // ===> _API_SET_VALUE_ENTRY_V2
	} API_SET_NAMESPACE_ENTRY_V2, * PAPI_SET_NAMESPACE_ENTRY_V2;

	typedef struct _API_SET_NAMESPACE_V2 {
		ULONG Version;
		ULONG Count;
		API_SET_NAMESPACE_ENTRY_V2 Array[ANYSIZE_ARRAY];
	} API_SET_NAMESPACE_V2, * PAPI_SET_NAMESPACE_V2;

	///////////////////////////////////////////////////////////////////////////////
	// ApiSet v4

	typedef struct _API_SET_VALUE_ENTRY_REDIRECTION_V4 {
		ULONG Flags;
		ULONG NameOffset;
		ULONG NameLength;
		ULONG ValueOffset;
		ULONG ValueLength;
	} API_SET_VALUE_ENTRY_REDIRECTION_V4, * PAPI_SET_VALUE_ENTRY_REDIRECTION_V4;

	typedef struct _API_SET_VALUE_ENTRY_V4 {
		ULONG Flags;
		ULONG NumberOfRedirections;
		API_SET_VALUE_ENTRY_REDIRECTION_V4 Redirections[ANYSIZE_ARRAY];
	} API_SET_VALUE_ENTRY_V4, * PAPI_SET_VALUE_ENTRY_V4;

	typedef struct _API_SET_NAMESPACE_ENTRY_V4 {
		ULONG Flags;
		ULONG NameOffset;
		ULONG NameLength;
		ULONG AliasOffset;
		ULONG AliasLength;
		ULONG DataOffset; // ===> _API_SET_VALUE_ENTRY_V4
	} API_SET_NAMESPACE_ENTRY_V4, * PAPI_SET_NAMESPACE_ENTRY_V4;

	typedef struct _API_SET_NAMESPACE_V4 {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		API_SET_NAMESPACE_ENTRY_V4 Array[ANYSIZE_ARRAY];
	} API_SET_NAMESPACE_V4, * PAPI_SET_NAMESPACE_V4;

	///////////////////////////////////////////////////////////////////////////////
	// ApiSet v6

	typedef struct _API_SET_HASH_ENTRY_V6 {
		ULONG Hash;
		ULONG Index;
	} API_SET_HASH_ENTRY_V6, * PAPI_SET_HASH_ENTRY_V6;

	typedef struct _API_SET_NAMESPACE_ENTRY_V6 {
		ULONG Flags;
		ULONG NameOffset;
		ULONG NameLength;
		ULONG HashedLength;
		ULONG ValueOffset;
		ULONG ValueCount;
	} API_SET_NAMESPACE_ENTRY_V6, * PAPI_SET_NAMESPACE_ENTRY_V6;

	typedef struct _API_SET_VALUE_ENTRY_V6 {
		ULONG Flags;
		ULONG NameOffset;
		ULONG NameLength;
		ULONG ValueOffset;
		ULONG ValueLength;
	} API_SET_VALUE_ENTRY_V6, * PAPI_SET_VALUE_ENTRY_V6;

	typedef struct _API_SET_NAMESPACE_V6 {
		ULONG Version;
		ULONG Size;
		ULONG Flags;
		ULONG Count;
		ULONG EntryOffset;
		ULONG HashOffset;
		ULONG HashFactor;
	} API_SET_NAMESPACE_V6, * PAPI_SET_NAMESPACE_V6;

	typedef struct _API_SET_NAMESPACE_UNION {
		union
		{
			ULONG Version;
			API_SET_NAMESPACE_V2 ApiSetNameSpaceV2;
			API_SET_NAMESPACE_V4 ApiSetNameSpaceV4;
			API_SET_NAMESPACE_V6 ApiSetNameSpaceV6;
		};
	} API_SET_NAMESPACE_UNION, * PAPI_SET_NAMESPACE_UNION;
	
	///////////////////////////////////////////////////////////////////////////////

	typedef std::vector<std::wstring> ApiSetTarget;

	class ApiSetSchemaBase
	{
	public:
		virtual ~ApiSetSchemaBase() {};
		virtual std::vector<std::pair<std::wstring, ApiSetTarget> > GetAll() = 0;
		virtual ApiSetTarget Lookup(std::wstring) = 0;
	};

	class EmptyApiSetSchema sealed : public ApiSetSchemaBase
	{
	public:
		virtual std::vector<std::pair<std::wstring, ApiSetTarget>> GetAll() { return std::vector<std::pair<std::wstring, ApiSetTarget>>(); }
		virtual ApiSetTarget Lookup(std::wstring) { return ApiSetTarget(); }
	};

	struct ApiSetSchemaImpl
	{
		static std::unique_ptr<ApiSetSchemaBase> ParseApiSetSchema(const API_SET_NAMESPACE_UNION* apiSetMap);

	private:
		// private implementation of ApiSet schema parsing
		static std::unique_ptr<ApiSetSchemaBase> GetApiSetSchemaV2(const API_SET_NAMESPACE_V2* map);
		static std::unique_ptr<ApiSetSchemaBase> GetApiSetSchemaV4(const API_SET_NAMESPACE_V4* map);
		static std::unique_ptr<ApiSetSchemaBase> GetApiSetSchemaV6(const API_SET_NAMESPACE_V6* map);
	};

	PAPI_SET_NAMESPACE_UNION GetApiSetNamespace();
}
