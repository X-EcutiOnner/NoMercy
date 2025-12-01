#pragma once
#include "Splash.hpp"

#undef GetServiceDisplayName

#define LOCK_MTX std::lock_guard <std::recursive_mutex> __lock(m_rmMutex)

namespace NoMercyCore
{
	enum class ECommonPhaseKeys : uint8_t
	{
		COMMON_I18N_NULL,
		COMMON_I18N_OK,
		COMMON_I18N_CANCEL,
		COMMON_I18N_CONTACT_ADMIN,
		COMMON_I18N_WEB_CONTACT_ADDRESS,
		COMMON_I18N_PHASE_PRE,
		COMMON_I18N_PHASE_INIT,
		COMMON_I18N_PHASE_POST
	};

	enum class ELocalizationPhase : uint8_t
	{
		I18N_PHASE_NULL,
		I18N_PHASE_COMMON,
		I18N_PHASE_TELEMETRY,
		I18N_PHASE_LAUNCHER_UPDATER,
		I18N_PHASE_SETUP,
		I18M_PHASE_PRE,
		I18N_PHASE_INIT,
		I18N_PHASE_POST
	};

	struct SI18nContext
	{
		uint8_t phase{ 0 };
		uint32_t index{ 0 };
		uint32_t sub_code{ 0 };
		std::wstring context{ L"" };
	};

	class CInitilizationManager : public CSingleton <CInitilizationManager>
	{
		public:
			CInitilizationManager();
			virtual ~CInitilizationManager();

			std::wstring GetI18nW(const uint8_t phase, const uint32_t id, const uint32_t sub_id = 0);
			std::wstring GetI18nW(const ELocalizationPhase phase, const uint32_t id, const uint32_t sub_id = 0);

			bool LoadLocalizationFile(const uint8_t app_type, const HINSTANCE hInstance, uint8_t& fail_step);

			void SetSplashImagePtr(CSplash* pSplash) { LOCK_MTX; m_pSplash = pSplash; };
			bool LoadSplashImage(const HINSTANCE hInstance);
			void CloseSplashImage();

			auto GetI18N() const  { LOCK_MTX; return m_vLanguageData; };
			auto GetNoMercyPath() const { LOCK_MTX; return m_stNoMercyPath; };

			bool IsProcessProtected();
			int	 CheckElevation();
			bool RequestPrivilege(const ULONG ulPriv);

			bool RestartCurrentProcessAsAdmin();
			bool StartAsAdmin(const std::wstring& file, const std::wstring& param, int& error);
			bool StartAsAdminNative(const std::wstring& file, const std::wstring& param, int& error);

			void SetNoMercyPath(const std::wstring& stPath);

		protected:
			bool __ProcessLocalizationData(const std::wstring& stBuffer, uint8_t& fail_step);

		private:
			mutable std::recursive_mutex m_rmMutex;
			
			std::vector <std::shared_ptr <SI18nContext>> m_vLanguageData;

			std::wstring m_stNoMercyPath;

			CSplash* m_pSplash{ nullptr };
	};
};

#undef LOCK_MTX
