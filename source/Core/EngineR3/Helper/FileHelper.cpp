#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ProcessHelper.hpp"
#include "FileHelper.hpp"

namespace NoMercy
{
	static std::wstring GetAbsolutePath(const std::wstring& path)
	{
		wchar_t wszBuffer[MAX_PATH]{ '\0' };
		_wfullpath(wszBuffer, path.c_str(), MAX_PATH);

		return wszBuffer;
	}
	
	CFile::CFile() :
		m_wstFileName(L""), m_wstName(L""), m_pOwnerProcess(nullptr), m_fileHandle(nullptr), m_mapHandle(nullptr), m_mappedData(nullptr), m_mappedSize(0),
		m_rawData(nullptr), m_rawSize(0), m_currPos(0), m_memOwner(false), m_fileType(EFileType::FILE_TYPE_NONE)
	{
	}
	CFile::CFile(std::wstring wstFileName, EFileType fileType, CProcess* Process) :
		m_wstFileName(wstFileName), m_wstName(L""), m_pOwnerProcess(nullptr), m_fileHandle(nullptr), m_mapHandle(nullptr), m_mappedData(nullptr), m_mappedSize(0),
		m_rawData(nullptr), m_rawSize(0), m_currPos(0), m_memOwner(false), m_fileType(EFileType::FILE_TYPE_NONE)
	{
	}
	CFile::~CFile()
	{
		m_pOwnerProcess = nullptr;

		Close();
	}

	// moveable
	inline CFile::CFile(CFile&& other) noexcept
	{
		*this = std::forward<CFile>(other);
	}
	inline CFile& CFile::operator=(CFile&& other) noexcept
	{
		std::swap(m_wstFileName, other.m_wstFileName);
		std::swap(m_wstName, other.m_wstName);
		std::swap(m_pOwnerProcess, other.m_pOwnerProcess);
		std::swap(m_fileHandle, other.m_fileHandle);
		std::swap(m_mapHandle, other.m_mapHandle);
		std::swap(m_mappedData, other.m_mappedData);
		std::swap(m_mappedSize, other.m_mappedSize);
		std::swap(m_rawData, other.m_rawData);
		std::swap(m_rawSize, other.m_rawSize);
		std::swap(m_currPos, other.m_currPos);
		std::swap(m_memOwner, other.m_memOwner);
		std::swap(m_fileType, other.m_fileType);

		return *this;
	}

	inline CFile::operator bool() noexcept
	{
		return IsValid();
	}

	bool CFile::Create(EFileMode filemode, bool map, bool silent_failure)
	{
		if (m_wstFileName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File name empty!");
			return false;
		}

		Close();

		auto filename_conv = GetAbsolutePath(m_wstFileName);

		APP_TRACE_LOG(LL_TRACE, L"File: %ls(%ls) Mode: %u", m_wstFileName.c_str(), filename_conv.c_str(), filemode);

		uint32_t dwMode = 0, dwShareMode = FILE_SHARE_READ;
		if (filemode == EFileMode::FILEMODE_WRITE)
		{
			dwMode = GENERIC_READ | GENERIC_WRITE;
			dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
		}
		else
		{
			dwMode = GENERIC_READ;
			dwShareMode = FILE_SHARE_READ;
		}

		m_fileHandle = g_winAPIs->CreateFileW(
			m_wstFileName.c_str(), dwMode, dwShareMode, nullptr, filemode == EFileMode::FILEMODE_READ ? OPEN_EXISTING : OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr
		);
		if (IS_VALID_HANDLE(m_fileHandle))
		{
			m_fileType = EFileType::FILE_TYPE_OUTPUT;
			m_wstName = filename_conv;

			if (map)
				return Map(0, 0);
			return true;
		}
		
		if (!silent_failure)
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls can not created! Error: %u", m_wstFileName.c_str(), g_winAPIs->GetLastError());
		}
		return false;
	}

	bool CFile::Open(bool silent_failure)
	{
		if (m_wstFileName.empty())
		{
			APP_TRACE_LOG(LL_ERR, L"File name empty!");
			return false;
		}

		Close();

		APP_TRACE_LOG(LL_TRACE, L"File: %ls", m_wstFileName.c_str());

		m_fileHandle = g_winAPIs->CreateFileW(m_wstFileName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (IS_VALID_HANDLE(m_fileHandle))
		{
			m_fileType = EFileType::FILE_TYPE_INPUT;
			m_wstName = GetAbsolutePath(m_wstFileName);
			return true;
		}
		
		if (!silent_failure)
		{
			APP_TRACE_LOG(LL_ERR, L"File: %ls can not open! Error: %u", m_wstFileName.c_str(), g_winAPIs->GetLastError());
		}
		return false;
	}

	void CFile::SetFileName(std::wstring wstFileName)
	{
		m_wstFileName = wstFileName;
		m_wstName = GetAbsolutePath(wstFileName);
	}
	void CFile::Close()
	{
//		if (m_wstFileName.size() > 0)
//		{
//			APP_TRACE_LOG(LL_SYS, L"%ls", m_wstFileName.c_str());
//		}

		if (m_rawData)
		{
			if (m_rawData != m_mappedData && m_memOwner)
			{
				CMemHelper::Free(m_rawData);
			}
			m_rawData = nullptr;
		}

		if (m_mappedData)
		{
			g_winAPIs->UnmapViewOfFile(m_mappedData);
			m_mappedData = nullptr;
		}

		if (IS_VALID_HANDLE(m_mapHandle))
		{
			g_winAPIs->CloseHandle(m_mapHandle);
			m_mapHandle = nullptr;
		}

		if (IS_VALID_HANDLE(m_fileHandle))
		{
			g_winAPIs->CloseHandle(m_fileHandle);
			m_fileHandle = INVALID_HANDLE_VALUE;
		}

		m_currPos = 0;
		m_rawSize = 0;
		m_mappedSize = 0;
		m_wstName.clear();
		m_wstFileName.clear();
		m_fileType = EFileType::FILE_TYPE_NONE;
		m_memOwner = false;
	}

	bool CFile::Map(uint64_t offset, uint32_t size)
	{
		Close();

		APP_TRACE_LOG(LL_TRACE, L"%ls", m_wstFileName.c_str());

		m_fileHandle = g_winAPIs->CreateFileW(GetAbsolutePath(m_wstFileName).c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
		if (!IS_VALID_HANDLE(m_fileHandle))
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFile fail! Error: %u", g_winAPIs->GetLastError());
			return false;
		}

		m_mapHandle = g_winAPIs->CreateFileMappingW(m_fileHandle, nullptr, PAGE_READONLY, 0, 0, nullptr);
		if (!m_mapHandle)
		{
			APP_TRACE_LOG(LL_ERR, L"CreateFileMapping fail! File: %ls Error: %u", m_wstFileName.c_str(), GetLastError());

			g_winAPIs->CloseHandle(m_fileHandle);
			m_fileHandle = INVALID_HANDLE_VALUE;
			return false;
		}

		SYSTEM_INFO sys{};
		g_winAPIs->GetSystemInfo(&sys);

		offset -= offset % sys.dwAllocationGranularity;

		m_mappedData = static_cast<uint8_t*>(g_winAPIs->MapViewOfFile(m_mapHandle, FILE_MAP_READ, offset >> 32, offset & 0xffffffff, size));

		LARGE_INTEGER s;
		g_winAPIs->GetFileSizeEx(m_fileHandle, &s);
		if (size == 0)
		{
			size = static_cast<uint32_t>(s.QuadPart);
		}
		m_mappedSize = size;

		m_rawData = m_mappedData + (offset % sys.dwAllocationGranularity);
		m_rawSize = std::min<uint64_t>(size, s.QuadPart);

		APP_TRACE_LOG(LL_TRACE, L"%ls, %llu, %u/%u", m_wstFileName.c_str(), offset, size, (uint32_t)m_rawSize);

		m_currPos = 0;

		if (m_rawData)
		{
			m_fileType = EFileType::FILE_TYPE_MAPPED;
			m_wstFileName = m_wstFileName;
			m_wstName = GetAbsolutePath(m_wstFileName);
		}

		return (m_rawData != nullptr);
	}

	bool CFile::Assign(const void* memory, uint32_t length, bool copy)
	{
		Close();

		APP_TRACE_LOG(LL_TRACE, L"%ls, %p, %u, %s", m_wstFileName.c_str(), memory, length, copy ? xorstr_(L"copy") : xorstr_(L"assign"));

		if (copy)
		{
			m_rawData = static_cast<uint8_t*>(CMemHelper::Allocate(length));
			if (m_rawData)
			{
				memcpy(m_rawData, memory, length);
				m_rawSize = length;
			}
			m_memOwner = true;
		}
		else
		{
			m_rawData = static_cast<uint8_t*>(const_cast<void*>(memory));
			m_rawSize = length;
			m_memOwner = false;
		}


		if (m_rawData)
		{
			m_fileType = EFileType::FILE_TYPE_MEMORY;
			m_wstFileName = m_wstFileName;
			m_wstName = GetAbsolutePath(m_wstFileName);
		}

		return m_rawData;
	}

	uint32_t CFile::Read(void* buffer, uint32_t size)
	{
		APP_TRACE_LOG(LL_TRACE, L"%ls, %p, %u", m_wstFileName.c_str(), buffer, size);

		if (!IsReadable())
			return 0;

		switch (m_fileType)
		{
			case EFileType::FILE_TYPE_OUTPUT:
			case EFileType::FILE_TYPE_INPUT:
			{
				DWORD cbRead = 0;
				if (!g_winAPIs->ReadFile(m_fileHandle, buffer, size, &cbRead, nullptr))
				{
					APP_TRACE_LOG(LL_ERR, L"ReadFile fail! Error: %u", GetLastError());
					return 0;
				}
				return cbRead;
			} break;

			case EFileType::FILE_TYPE_MAPPED:
			case EFileType::FILE_TYPE_MEMORY:
			{
				auto len = std::min<uint32_t>(static_cast<uint32_t>(m_rawSize - m_currPos), size);
				memcpy(buffer, &m_rawData[m_currPos], len);
				m_currPos += len;
				return len;
			} break;
		}

		return 0;
	}

	uint32_t CFile::Write(const void* buffer, uint32_t size)
	{
		APP_TRACE_LOG(LL_TRACE, L"%ls, %p, %u", m_wstFileName.c_str(), buffer, size);

		if (!IsWriteable())
			return 0;

		DWORD cbWritten = 0;
		if (!g_winAPIs->WriteFile(m_fileHandle, buffer, size, &cbWritten, nullptr))
		{
			APP_TRACE_LOG(LL_ERR, L"WriteFile fail! Error: %u", GetLastError());
			return 0;
		}

		return cbWritten;
	}

	int32_t CFile::Seek(uint32_t offset, ESeekType iSeekType)
	{
		APP_TRACE_LOG(LL_TRACE, L"%ls, %u, %d", m_wstFileName.c_str(), offset, iSeekType);

		if (!IsValid())
			return 0;

		switch (iSeekType)
		{
			case ESeekType::SEEK_TYPE_BEGIN:
				if (offset > GetSize())
					offset = GetSize();

				m_currPos = offset;
				break;

			case ESeekType::SEEK_TYPE_CURRENT:
				m_currPos = std::min(m_currPos + offset, GetSize());
				break;

			case ESeekType::SEEK_TYPE_END:
				m_currPos = (GetSize() >= offset) ? GetSize() - offset : 0;
				break;
		}

		return m_currPos;
	}

	void CFile::SetPosition(int64_t offset, bool relative)
	{
		APP_TRACE_LOG(LL_TRACE, L"%ls, %lld, %s", m_wstFileName.c_str(), offset, relative ? xorstr_(L"relative") : xorstr_(L"absolute"));

		if (!IsValid())
			return;

		switch (m_fileType)
		{
			case EFileType::FILE_TYPE_OUTPUT:
			case EFileType::FILE_TYPE_INPUT:
			{
				LARGE_INTEGER m;
				m.QuadPart = offset;

				if (!g_winAPIs->SetFilePointerEx(m_fileHandle, m, 0, relative ? FILE_CURRENT : FILE_BEGIN))
				{
					APP_TRACE_LOG(LL_ERR, L"SetFilePointerEx fail! Error: %u", GetLastError());
					return;
				}
			} break;

			case EFileType::FILE_TYPE_MAPPED:
			case EFileType::FILE_TYPE_MEMORY:
			{
				m_currPos = relative ? m_currPos + offset : offset;
			} break;
		}
	}

	bool CFile::IsValid() const
	{
		auto ret = false;
		switch (m_fileType)
		{
			case EFileType::FILE_TYPE_OUTPUT:
			case EFileType::FILE_TYPE_INPUT:
			{
				ret = m_fileHandle && m_fileHandle != INVALID_HANDLE_VALUE;
			} break;

			case EFileType::FILE_TYPE_MAPPED:
			case EFileType::FILE_TYPE_MEMORY:
			{
				ret = m_rawData != nullptr;
			} break;
		}

		return ret;
	}
	bool CFile::IsReadable() const
	{
		return IsValid();
	}
	bool CFile::IsWriteable() const
	{
		return (m_fileType == EFileType::FILE_TYPE_OUTPUT && IsValid());
	}

	EFileType CFile::GetFileType() const
	{
		return m_fileType;
	}

	const uint8_t* CFile::GetData() const
	{
		return reinterpret_cast<const uint8_t*>(m_rawData);
	}

	const std::wstring& CFile::GetName() const
	{
		return m_wstName;
	}

	const std::wstring& CFile::GetFileName() const
	{
		return m_wstFileName;
	}

	uint64_t CFile::GetSize() const
	{
		if (!IsValid())
			return 0;

		uint64_t size = 0;
		switch (m_fileType)
		{
			case EFileType::FILE_TYPE_OUTPUT:
			case EFileType::FILE_TYPE_INPUT:
			{
				LARGE_INTEGER s;
				g_winAPIs->GetFileSizeEx(m_fileHandle, &s);
				size = s.QuadPart;
			} break;

			case EFileType::FILE_TYPE_MAPPED:
			case EFileType::FILE_TYPE_MEMORY:
			{
				size = m_rawSize;
			} break;
		}

		return size;
	}
	uint64_t CFile::GetPosition() const
	{
		if (!IsValid())
			return 0;

		switch (m_fileType)
		{
			case EFileType::FILE_TYPE_OUTPUT:
			case EFileType::FILE_TYPE_INPUT:
			{
				LARGE_INTEGER newptr{};
				LARGE_INTEGER distance{};

				g_winAPIs->SetFilePointerEx(m_fileHandle, distance, &newptr, FILE_CURRENT);
				return newptr.QuadPart;
			} break;

			case EFileType::FILE_TYPE_MAPPED:
			case EFileType::FILE_TYPE_MEMORY:
			{
				return m_currPos;
			} break;
		}
		
		return 0;
	}

	const uint8_t* CFile::GetCurrentSeekPoint() const
	{
		return reinterpret_cast<uint8_t*>((uint64_t)GetData() + m_currPos);
	}
};
