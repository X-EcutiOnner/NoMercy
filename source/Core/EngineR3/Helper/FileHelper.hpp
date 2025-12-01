#pragma once

namespace NoMercy
{
	class CProcess;
	
	enum class EFileType : uint8_t
	{
		FILE_TYPE_NONE,
		FILE_TYPE_OUTPUT, // READ | WRITE (disk)
		FILE_TYPE_INPUT,  // WRITE ONLY (disk)
		FILE_TYPE_MAPPED, // READ ONLY (mapped)
		FILE_TYPE_MEMORY, // READ ONLY (memory)
		FILE_TYPE_MAX
	};
	enum class EFileMode : uint8_t
	{
		FILEMODE_READ = (1 << 0),
		FILEMODE_WRITE = (1 << 1)
	};
	enum class ESeekType : uint8_t
	{
		SEEK_TYPE_BEGIN = 0,
		SEEK_TYPE_CURRENT = 1,
		SEEK_TYPE_END = 2
	};

	class CFile
	{
	public:
		CFile();
		CFile(std::wstring wstFileName, EFileType fileType, CProcess* Process = nullptr);
		~CFile();

		// moveable
		CFile(CFile&& other) noexcept;
		CFile& operator=(CFile&& other) noexcept;

		explicit operator bool() noexcept;

		bool Create(EFileMode filemode, bool map, bool silent_failure = false);
		bool Open(bool silent = false);
		bool Map(uint64_t offset = 0, uint32_t size = 0);
		bool Assign(const void* memory, uint32_t length, bool copy = true);

		void SetFileName(std::wstring wstFileName);
		void Close();

		uint32_t Read(void* buffer, uint32_t size);
		uint32_t Write(const void* buffer, uint32_t size);

		int32_t Seek(uint32_t offset, ESeekType iSeekType);
		void SetPosition(int64_t offset, bool relative = false);

		bool IsValid() const;
		bool IsReadable() const;
		bool IsWriteable() const;

		EFileType GetFileType() const;
		const uint8_t* GetData() const;
		const std::wstring& GetFileName() const;
		const std::wstring& GetName() const;
		uint64_t GetSize() const;
		uint64_t GetPosition() const;
		const uint8_t* GetCurrentSeekPoint() const;

		// file funcs, dir funcs, version, certificate, hash

	private:
		std::wstring m_wstFileName;
		std::wstring m_wstName;
		CProcess* m_pOwnerProcess;

		HANDLE m_fileHandle;
		HANDLE m_mapHandle;

		uint8_t* m_mappedData;
		uint64_t m_mappedSize;

		uint8_t* m_rawData;
		uint64_t m_rawSize;

		uint64_t m_currPos;
		bool m_memOwner;
		EFileType m_fileType;
	};
}
