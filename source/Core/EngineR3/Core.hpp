#pragma once
#include "../../Common/AbstractSingleton.hpp"
#include "../../Core/EngineR3_Core/include/SafeExecutor.hpp"

namespace NoMercy
{
	class CCore : public CSingleton <CCore>
	{
		using TInstanceFunc = std::function<bool()>;

	public:
		CCore();
		virtual ~CCore();

		bool CreateInstance(uint8_t nAppID, LPCVOID c_lpModuleInfo = nullptr);
		bool ReleaseInstance() const;

		bool IsInstanceCreated() const;
		uint8_t GetAppID() const;
		LPCVOID GetModuleInfo() const;

	protected:
		inline void __ValidateCoreInstances();

	private:
		uint8_t	m_nAppID;
		std::atomic_bool	m_abHasInstance;
		LPCVOID m_lpModuleInfo;

		std::unique_ptr <CApplication> m_upApplication;
	};

	static CCore* gs_pkCoreInstance	= nullptr;
};
