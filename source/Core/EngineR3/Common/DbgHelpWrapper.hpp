#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace NoMercy
{
	class CDbgHelpWrapper
	{
		struct SYM_CHILD_ENTRY
		{
			std::string Name;
			std::string TypeName;
			UINT64 ElementsCount;
			UINT64 Size;
			ULONG Offset;
			BOOL IsBitField;
			ULONG BitPosition;
		};
		struct SYM_INFO
		{
			std::string Name;
			UINT64 Size;
			ULONG Offset;
			std::vector<SYM_CHILD_ENTRY> Entries;
		};
		// From cvconst.h:
		enum BasicType
		{
			btNoType = 0,
			btVoid = 1,
			btChar = 2,
			btWChar = 3,
			btInt = 6,
			btUInt = 7,
			btFloat = 8,
			btBCD = 9,
			btBool = 10,
			btLong = 13,
			btULong = 14,
			btCurrency = 25,
			btDate = 26,
			btVariant = 27,
			btComplex = 28,
			btBit = 29,
			btBSTR = 30,
			btHresult = 31
		};

	public:
		CDbgHelpWrapper(const std::string& stSymbolPath = "");
		~CDbgHelpWrapper();

		bool IsInitialized() const { return m_bInitialized; }

		// Load symbols for specified module (*.exe/*.dll/*.sys etc.):
		bool LoadModule(LPCSTR ModulePath, OPTIONAL DWORD64 ImageBase = 0, OPTIONAL DWORD ImageSize = 0);

		bool DumpSymbol(LPCSTR SymbolName, OUT SYM_INFO& SymInfo);

	protected:
		std::string GetSymName(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		std::string GetSymTypeName(ULONG Index, OPTIONAL OUT PUINT64 BaseTypeSize = nullptr, OPTIONAL OUT PBOOL Status = nullptr);
		UINT64 GetSymSize(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		ULONG GetSymOffset(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		ULONG GetSymAddressOffset(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		ULONG GetSymBitPosition(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		ULONG GetSymTypeId(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		ULONG GetSymArrayTypeId(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		enum SymTagEnum GetSymTag(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		enum BasicType GetSymType(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);
		enum BasicType GetSymBaseType(ULONG Index, OPTIONAL OUT PBOOL Status = nullptr);

	private:
		bool m_bInitialized;
		HANDLE m_hProcess;
		DWORD64 m_dwModuleBase;
	};
};
