#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include <DbgHelp.h>
#include "DbgHelpWrapper.hpp"

#if 0 
uint64_t EPNameOffset = 0;
uint64_t EPPidOffset = 0;
uint64_t EPDirBaseOffset = 0;
uint64_t EPBaseOffset = 0;
uint64_t EPLinkOffset = 0;
uint64_t EPObjectTable = 0;

char szCurrentDirectory[MAX_PATH] = { 0 };
if (!GetCurrentDirectoryA(MAX_PATH, szCurrentDirectory))
return;

char szSystemDirectory[MAX_PATH] = { 0 };
if (!GetSystemDirectoryA(szSystemDirectory, MAX_PATH))
return;

auto szKernelSysName = szSystemDirectory + std::string("\\ntoskrnl.exe");
auto szKernelLocalName = szCurrentDirectory + std::string("\\ntos.exe");

if (FALSE == CopyFileA(szKernelSysName.c_str(), szKernelLocalName.c_str(), FALSE)) // todo copy to temp foler
return;

auto pDbgHelpMgr = stdext::make_unique_nothrow<CDbgHelpWrapper>();
if (!pDbgHelpMgr || !pDbgHelpMgr.get())
{
	printf("Dbghel wrapper alloc fail! Error: %u\n", GetLastError());
	return;
}
printf("Dbghelper wrapper allocated!\n");

if (!pDbgHelpMgr->InitializeDbgHelp())
{
	printf("InitializeDbgHelp fail! Error: %u\n", GetLastError());
	return;
}
printf("Dbghelper wrapper initialized!\n");

if (!pDbgHelpMgr->LoadSymbols((char*)szKernelLocalName.c_str()))
{
	printf("LoadSymbols fail! Error: %u\n", GetLastError());
	return;
}
printf("Dbghelper wrapper symbols loaded!\n");

auto ulEprocessIdx = 0UL;
if (!pDbgHelpMgr->GetRootSymbol((char*)"_EPROCESS", &ulEprocessIdx))
{
	printf("GetRootSymbol _EPROCESS fail! Error: %u\n", GetLastError());
	return;
}
printf("EPROCESS Index: %u\n", ulEprocessIdx);

#define MAX_CHILD 512
ULONG ulEprocessChilds[MAX_CHILD];
ULONG ulEprocessChildCount = 0UL;
if (!pDbgHelpMgr->GetChildrenSymbols(ulEprocessIdx, ulEprocessChilds, MAX_CHILD, ulEprocessChildCount))
{
	printf("GetChildrenSymbols fail! Error: %u\n", GetLastError());
	return;
}
printf("Eprocess Child count: %u\n", ulEprocessChildCount);

for (ULONG i = 0; i < ulEprocessChildCount; i++)
{
	auto ulCurrChild = ulEprocessChilds[i];
	printf("Current index: %u Current child: %u\n", i, ulCurrChild);

	LPWSTR wszName = { L'\0' };
	if (!pDbgHelpMgr->GetSymbolName(ulCurrChild, &wszName))
	{
		printf("GetSymbolName fail! Error: %u\n", GetLastError());
		continue;
	}
	printf("Child: %u-%ls\n", ulCurrChild, wszName);

	auto ulCurrOffset = 0UL;
	if (!pDbgHelpMgr->GetSymbolOffset(ulCurrChild, &ulCurrOffset))
	{
		printf("GetSymbolOffset fail! Error: %u\n", GetLastError());
		continue;
	}
	printf("Offset: %ls -> %u\n", wszName, ulCurrOffset);

	if (!wcscmp(wszName, L"ImageFileName"))
	{
		EPNameOffset = ulCurrOffset;
	}
	else if (!wcscmp(wszName, L"UniqueProcessId"))
	{
		EPPidOffset = ulCurrOffset;
	}
	else if (!wcscmp(wszName, L"ActiveProcessLinks"))
	{
		EPLinkOffset = ulCurrOffset;
	}
	else if (!wcscmp(wszName, L"SectionBaseAddress"))
	{
		EPBaseOffset = ulCurrOffset;
	}
	else if (!wcscmp(wszName, L"ObjectTable"))
	{
		EPObjectTable = ulCurrOffset;
	}

	pDbgHelpMgr->FreeSymbolName(wszName);
}
#endif

namespace NoMercy
{
	CDbgHelpWrapper::CDbgHelpWrapper(const std::string& stSymbolPath) :
		m_bInitialized(false), m_hProcess(NtCurrentProcess()), m_dwModuleBase(0)
	{
		const auto c_szDefaultSymbolPath = xorstr_("srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
		m_bInitialized = g_winAPIs->SymInitialize(m_hProcess, !stSymbolPath.empty() ? stSymbolPath.c_str() : c_szDefaultSymbolPath, FALSE);
	}
	CDbgHelpWrapper::~CDbgHelpWrapper()
	{
		if (m_bInitialized)
		{
			g_winAPIs->SymCleanup(m_hProcess);
			m_bInitialized = false;
		}
	}

	bool CDbgHelpWrapper::LoadModule(LPCSTR ModulePath, OPTIONAL DWORD64 ImageBase, OPTIONAL DWORD ImageSize)
	{
		m_dwModuleBase = g_winAPIs->SymLoadModuleEx(m_hProcess, NULL, ModulePath, NULL, ImageBase, ImageSize, NULL, 0);
		return !!m_dwModuleBase;
	}

	std::string CDbgHelpWrapper::GetSymName(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		LPCSTR Name = nullptr;

		if (g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_SYMNAME, &Name) && Name)
		{
			std::string SymName = Name;

			g_winAPIs->VirtualFree(const_cast<LPSTR>(Name), 0, MEM_RELEASE);
			if (Status)
				*Status = TRUE;
			return SymName;
		}

		if (Status)
			*Status = FALSE;
		return "";
	}

	std::string CDbgHelpWrapper::GetSymTypeName(ULONG Index, OPTIONAL OUT PUINT64 BaseTypeSize, OPTIONAL OUT PBOOL Status)
	{
		if (!Index)
			return "";

		UINT64 SymSize = this->GetSymSize(Index, Status);
		if (BaseTypeSize)
			*BaseTypeSize = SymSize;

		std::string TypeName = this->GetSymName(Index, Status);
		if (!TypeName.empty())
			return TypeName;

		enum SymTagEnum Tag = this->GetSymTag(Index, Status);
		switch (Tag)
		{
		case SymTagBaseType:
		{
			enum CDbgHelpWrapper::BasicType Type = this->GetSymBaseType(Index, Status);
			switch (Type)
			{
				case btNoType:
					TypeName = xorstr_("NO_TYPE");
					break;
				case btVoid:
					TypeName = xorstr_("VOID");
					break;
				case btChar:
					TypeName = xorstr_("CHAR");
					break;
				case btWChar:
					TypeName = xorstr_("WCHAR");
					break;
				case btInt:
					TypeName = SymSize == sizeof(INT64) ? xorstr_("INT64") : xorstr_("INT");
					break;
				case btUInt:
					TypeName = SymSize == sizeof(UINT64) ? xorstr_("UINT64") : xorstr_("UINT");
					break;
				case btFloat:
					TypeName = xorstr_("float");
					break;
				case btBCD:
					TypeName = xorstr_("BCD"); // Binary-coded decimal
					break;
				case btBool:
					TypeName = xorstr_("BOOL");
					break;
				case btLong:
					TypeName = SymSize == sizeof(LONGLONG) ? xorstr_("LONGLONG") : xorstr_("LONG");
					break;
				case btULong:
					TypeName = SymSize == sizeof(ULONGLONG) ? xorstr_("ULONGLONG") : xorstr_("ULONG");
					break;
				case btCurrency:
					TypeName = xorstr_("CurrencyType"); // ???
					break;
				case btDate:
					TypeName = xorstr_("DateType"); // ???
					break;
				case btVariant:
					TypeName = xorstr_("VariantType"); // ???
					break;
				case btComplex:
					TypeName = xorstr_("ComplexType"); // ???
					break;
				case btBit:
					TypeName = xorstr_("Bit");
					break;
				case btBSTR:
					TypeName = xorstr_("BSTR"); // Binary string
					break;
				case btHresult:
					TypeName = xorstr_("HRESULT");
					break;
				}
				break;
			}
			case SymTagPointerType:
			{
				ULONG Type = this->GetSymType(Index, Status);
				TypeName = this->GetSymTypeName(Type, BaseTypeSize, Status) + xorstr_("*");
				break;
			}
			case SymTagArrayType:
			{
				ULONG Type = this->GetSymArrayTypeId(Index, Status);
				TypeName = this->GetSymTypeName(Type, BaseTypeSize, Status);
				break;
			}
			default:
			{
				ULONG Type = this->GetSymType(Index, Status);
				TypeName = this->GetSymTypeName(Type, BaseTypeSize, Status);
			}
		}

		return TypeName;
	}

	UINT64 CDbgHelpWrapper::GetSymSize(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		UINT64 Size = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_LENGTH, &Size);
		if (Status)
			*Status = SymStatus;

		return Size;
	}

	ULONG CDbgHelpWrapper::GetSymOffset(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG Offset = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_OFFSET, &Offset);
		if (Status)
			*Status = SymStatus;

		return Offset;
	}

	ULONG CDbgHelpWrapper::GetSymAddressOffset(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG Offset = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_ADDRESSOFFSET, &Offset);
		if (Status)
			*Status = SymStatus;

		return Offset;
	}

	ULONG CDbgHelpWrapper::GetSymBitPosition(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG BitPosition = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_BITPOSITION, &BitPosition);
		if (Status)
			*Status = SymStatus;

		return BitPosition;
	}

	ULONG CDbgHelpWrapper::GetSymTypeId(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG TypeId = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_TYPEID, &TypeId);
		if (Status)
			*Status = SymStatus;

		return TypeId;
	}

	ULONG CDbgHelpWrapper::GetSymArrayTypeId(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG TypeId = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_ARRAYINDEXTYPEID, &TypeId);
		if (Status)
			*Status = SymStatus;

		return TypeId;
	}

	enum SymTagEnum CDbgHelpWrapper::GetSymTag(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG Tag = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_SYMTAG, &Tag);
		if (Status)
			*Status = SymStatus;

		return static_cast<enum SymTagEnum>(Tag);
	}

	enum CDbgHelpWrapper::BasicType CDbgHelpWrapper::GetSymType(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG Type = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_TYPE, &Type);
		if (Status)
			*Status = SymStatus;

		return static_cast<enum BasicType>(Type);
	}

	enum CDbgHelpWrapper::BasicType CDbgHelpWrapper::GetSymBaseType(ULONG Index, OPTIONAL OUT PBOOL Status)
	{
		ULONG BasicType = 0;

		BOOL SymStatus = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, Index, TI_GET_BASETYPE, &BasicType);
		if (Status)
			*Status = SymStatus;

		return static_cast<enum BasicType>(BasicType);
	}


	bool CDbgHelpWrapper::DumpSymbol(LPCSTR SymbolName, OUT SYM_INFO& SymInfo)
	{
		SymInfo = {};

		// Obtaining root symbol:
		const ULONG SymNameLength = 128;
		const ULONG SymInfoSize = sizeof(SYMBOL_INFO) + SymNameLength * sizeof(WCHAR);

		std::vector <BYTE> RootSymbolInfoBuffer(SymInfoSize);
		auto RootSymbolInfo = reinterpret_cast<PSYMBOL_INFO>(&RootSymbolInfoBuffer[0]);
		RootSymbolInfo->SizeOfStruct = SymInfoSize;
	
		BOOL Status = g_winAPIs->SymGetTypeFromName(m_hProcess, m_dwModuleBase, SymbolName, RootSymbolInfo);
		if (!Status)
			return false;

		ULONG RootIndex = RootSymbolInfo->Index;

		SymInfo.Name = this->GetSymName(RootIndex);
		SymInfo.Size = this->GetSymSize(RootIndex);
		SymInfo.Offset = this->GetSymOffset(RootIndex, &Status);
		if (!Status)
			SymInfo.Offset = this->GetSymAddressOffset(RootIndex);

		// Obtaining root symbol children count:
		ULONG ChildrenCount = 0;
		Status = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, RootIndex, TI_GET_CHILDRENCOUNT, &ChildrenCount);
		if (!Status)
			return false;

		SymInfo.Name = SymbolName;
		g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, RootIndex, TI_GET_LENGTH, &SymInfo.Size);

		if (ChildrenCount)
		{
			// Obtaining children indices:
			std::vector <BYTE> FindChildrenParamsBuffer(sizeof(TI_FINDCHILDREN_PARAMS) + ChildrenCount * sizeof(ULONG));

			const auto Children = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(&FindChildrenParamsBuffer[0]);
			Children->Count = ChildrenCount;

			Status = g_winAPIs->SymGetTypeInfo(m_hProcess, m_dwModuleBase, RootIndex, TI_FINDCHILDREN, Children);
			if (!Status)
				return false;

			for (std::size_t i = 0; i < ChildrenCount; i++)
			{
				SYM_CHILD_ENTRY Entry = {};
				ULONG ChildIndex = Children->ChildId[i];
				ULONG TypeId = this->GetSymTypeId(ChildIndex);
				Entry.Name = this->GetSymName(ChildIndex);
				Entry.Size = this->GetSymSize(TypeId);
				Entry.Offset = this->GetSymOffset(ChildIndex);
				Entry.BitPosition = this->GetSymBitPosition(ChildIndex, &Entry.IsBitField);
				UINT64 BaseTypeSize = 0;
				Entry.TypeName = this->GetSymTypeName(TypeId, &BaseTypeSize);
				Entry.ElementsCount = BaseTypeSize != 0 ? Entry.Size / BaseTypeSize : 1;

				if (Entry.Name.empty())
					Entry.Name = xorstr_("UNKNOWN_NAME");
				if (Entry.TypeName.empty())
					Entry.TypeName = xorstr_("UNKNOWN_TYPE");

				SymInfo.Entries.emplace_back(Entry);
			}
		}

		return true;
	}
};
