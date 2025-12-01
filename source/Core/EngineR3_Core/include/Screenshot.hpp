#pragma once

#define LOCK_MTX std::lock_guard <std::recursive_mutex> __lock(m_rmMutex)

namespace NoMercyCore
{
	struct SScreenshotData
	{
		LPVOID buffer;
		std::size_t length;
	};

	class CScreenshotMgr : public CSingleton <CScreenshotMgr>
	{
	public:
		CScreenshotMgr();
		virtual ~CScreenshotMgr();

		std::vector <SScreenshotData> CreateScreenshots();
		void AppendScreenshot(const SScreenshotData& data);
		void ClearScreenshotBuffer();

		auto GetScreenshots() const		{ LOCK_MTX; return m_vScreenshots; };
		auto GetScreenshotSize() const	{ LOCK_MTX; return m_vScreenshots.size(); };

	private:
		mutable std::recursive_mutex m_rmMutex;
		std::vector <SScreenshotData> m_vScreenshots;
	};
};

#undef LOCK_MTX
