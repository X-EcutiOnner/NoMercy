#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include <vector>
#include <memory>

namespace NoMercyCore
{
	class CSyscallIndexHelper
	{
	public:
		CSyscallIndexHelper();
		~CSyscallIndexHelper();

		bool BuildAllSyscalls();
		bool BuildSyscallList(bool bFromFile = true);

		ULONG ExtractSyscallNumber(LPCSTR FunctionName);

		DWORD GetSyscallIdFromFile(const std::string& stFunction);
		DWORD GetSyscallIdFromMemory(const std::string& stFunction);
		DWORD GetSyscallId(const std::string& stFunction);

	protected:
		bool ParseFromNtdllFile(const std::string& szAPIName, LPDWORD pdwSysIndex);
		bool AppendFunctionID(const std::string& stFunction, bool bFromFile);
		inline DWORD GetFunctionHash(const std::string& stFunction);

	private:
		std::map <DWORD /* dwFuncHash */, DWORD /* dwSyscallID */> m_syscall_indexes;
	};
};
