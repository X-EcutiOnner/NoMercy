#pragma once

namespace NoMercy
{
	class CGameIntegrationManager : public std::enable_shared_from_this <CGameIntegrationManager>
	{
	public:
		CGameIntegrationManager() = default;
		virtual ~CGameIntegrationManager() = default;

		bool LoadPackedBundleFile(const std::wstring& stFileName, uint8_t& pFailStep);

	protected:
		bool ProcessBundleFileData(const std::wstring& stContent, uint8_t& pFailStep);

	private:
		std::map <std::wstring, std::wstring> m_mapVirtualFileHashList;
	};
};
