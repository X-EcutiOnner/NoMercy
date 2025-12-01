#pragma once

namespace NoMercy
{
	enum ECacheRequestTypes : uint8_t
	{
		NONE,
		SHA1,
		SHA256_REGION
	};

	using TCacheBuffer = std::map <std::wstring, std::wstring>;
	using TCacheRequestBuffer = std::tuple <ECacheRequestTypes, std::wstring>;
	class CCacheManager : public std::enable_shared_from_this <CCacheManager>
	{		
	public:
		CCacheManager();
		virtual ~CCacheManager();

		bool InitializeThread() const;
		void ReleaseThread();

		std::wstring GetCachedValue(const std::wstring& wstKey) const;
		void RegisterCacheValue(const std::wstring& wstKey, const std::wstring& wstValue);
		void DeleteCachedValue(const std::wstring& wstKey);

		bool SaveCachesToDBFile(const std::wstring& wstFilename) const;
		bool LoadSavedCachesFromDBFile(const std::wstring& wstFilename) const;

		std::wstring GetCachedFileSHA1(const std::wstring& wstFilename) const;
		std::wstring GetCachedRegionSHA256(DWORD dwProcessID, uint64_t pMemBase) const;

		std::wstring GetCacheRequestTypeStr(const ECacheRequestTypes& type) const;
		bool IsAlreadyCachedRequest(TCacheRequestBuffer kNode) const;
		void AppendToRequestQueue(TCacheRequestBuffer kNode);

	protected:
		void __CacheRunningProcessSHA1Hashes();
		void __CacheRunningProcessRegionSHA256Hashes();

		bool ProcessRequestNode(std::shared_ptr <TCacheRequestBuffer> spNode);
		std::shared_ptr <TCacheRequestBuffer> DequeueRequestCacheNode();

	protected:
		DWORD					CacheManagerThreadProcessor(void);
		static DWORD WINAPI		StartThreadRoutine(LPVOID lpParam);

	private:
		mutable std::recursive_mutex m_rmLock;
		std::atomic_bool m_abReleaseStarted;

		PVOID m_pvFSRedirectionCache;
		TCacheBuffer m_mapCache;
		std::vector <std::wstring> m_vecSkippedFile;
		moodycamel::ConcurrentQueue <std::shared_ptr <TCacheRequestBuffer>> m_kCacheRequests;
	};
}
