#pragma once
#include <phnt_windows.h>
#include <phnt.h>
#include <string>
#include "NetworkAdapter.hpp"

namespace NoMercyCore
{
	class CMacAddress
	{
	public:
		CMacAddress();
		~CMacAddress();

		bool FindPhysicalMacAddress();

		auto GetMacAddress() const { return m_wstPrimaryAdapterAddress; };
		auto GetPhysicalMacAddress() const { return m_wstPhysicalMacAddress; };

	protected:
		bool InitAdapters();
		bool FindValidMac();
		bool IsPrimaryAdapter(std::uint32_t dwIndex);
		void SetMacAdapterInfo(const std::wstring& szAdapterAddress, const std::wstring& szAdapterName);

	private:
		CNetworkAdapter*	m_pAdapters;
		std::uint32_t		m_nCount;

		std::wstring			m_wstPrimaryAdapterAddress;
		std::wstring			m_wstPrimaryAdapterName;
		std::wstring			m_wstPhysicalMacAddress;
	};
};
