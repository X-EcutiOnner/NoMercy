#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "PdbHelperDia.hpp"
#include <dia2.h>

namespace NoMercy
{
	PdbHelper::PdbHelper() :
		m_global(nullptr), m_session(nullptr), m_source(nullptr)
	{
	}
	PdbHelper::~PdbHelper()
	{
		// Must be released before CoUninitialize
		if (m_global)
		{
			m_global->Release();
			m_global = nullptr;
		}
		if (m_session)
		{
			m_session->Release();
			m_session = nullptr;
		}
		if (m_source)
		{
			m_source->Release();
			m_source = nullptr;
		}
	}

	bool PdbHelper::init(const std::wstring& filepath, const std::wstring& local_cache_path)
	{
		HRESULT hr = g_winAPIs->CoInitialize(nullptr);
		if (S_OK != hr && S_FALSE != hr && RPC_E_CHANGED_MODE != hr)
			return false;

		auto full_path = std::filesystem::absolute(local_cache_path);
		if (!std::filesystem::exists(full_path))
			if (!std::filesystem::create_directory(full_path))
				return false;

		auto symbol_path = this->make_symbol_path(full_path.wstring());

		// dia source
		m_source = this->create_ida_source();
		if (nullptr == m_source)
			return false;

		// load pdb
		hr = m_source->loadDataForExe(filepath.c_str(), symbol_path.c_str(), nullptr);
		if (S_OK != hr)
			return false;
		hr = m_source->openSession(&m_session);
		if (S_OK != hr)
			return false;
		hr = m_session->get_globalScope(&m_global);
		if (S_OK != hr)
			return false;

		if (!this->populate_symbols())
			return false;

		return true;
	}

	IDiaDataSource* PdbHelper::create_ida_source()
	{
		IDiaDataSource* source = nullptr;
		// Try to get from COM
		HRESULT hr = g_winAPIs->CoCreateInstance(CLSID_DiaSource,
			nullptr,
			CLSCTX_INPROC_SERVER,
			__uuidof(IDiaDataSource),
			reinterpret_cast<void**>(&m_source)
		);

		if (hr == REGDB_E_CLASSNOTREG)
		{
			// Retry with direct export call

			// load library
			HMODULE msdia140 = g_winAPIs->LoadLibraryW(xorstr_(L"msdia140.dll"));
			if (!msdia140)
				return false;

			// get DllGetClassObject
			using fGetClassObject = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);

			auto proc_name = make_DllGetClassObject();
			auto DllGetClassObject = reinterpret_cast<fGetClassObject>(g_winAPIs->GetProcAddress(msdia140, proc_name));

			if (!DllGetClassObject)
				return false;

			// get IClassFactory
			IClassFactory* classFactory;
			hr = DllGetClassObject(CLSID_DiaSource, IID_IClassFactory, reinterpret_cast<void**>(&classFactory));
			if (S_OK != hr)
				return false;

			// create instance
			hr = classFactory->CreateInstance(nullptr, IID_IDiaDataSource, reinterpret_cast<void**>(&source));

			return source;
		}
		return source;
	}

	bool PdbHelper::populate_symbols()
	{
		IDiaEnumSymbols* enumurator;
		auto hr = m_global->findChildren(SymTagNull, nullptr, nsNone, &enumurator);
		if (S_OK != hr)
			return false;

		ULONG count = 0;
		IDiaSymbol* isymbol;
		while (S_OK == (enumurator->Next(1, &isymbol, &count)) && count != 0)
		{
			DWORD rva = 0;
			wchar_t* name = nullptr;

			isymbol->get_relativeVirtualAddress(&rva);
			isymbol->get_undecoratedName(&name);

			if (name && rva)
			{
				std::wstring wname(name);

				// Remove x86 __stdcall decoration
				if (wname[0] == L'@' || wname[0] == L'_')
				{
					wname.erase(0, 1);
				}

				auto pos = wname.rfind(L'@');
				if (pos != wname.npos)
				{
					wname.erase(pos);
				}

				m_cache.emplace(wname, rva);
			}

			isymbol->Release();
		}
		enumurator->Release();
		return true;
	}
}
