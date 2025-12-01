#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "SharedMemory.hpp"

// TODO: Game client to service communication

namespace NoMercy
{
	ShareMemory::ShareMemory(const std::wstring& stName) :
		m_stName(stName), m_buf(nullptr), m_handle(nullptr), m_file(nullptr), m_hLockMtx(nullptr)
	{
		memset(&m_shareMemInfo, 0, sizeof(m_shareMemInfo));

		SYSTEM_INFO si{ 0 };
		g_winAPIs->GetSystemInfo(&si);
		m_dwAllocGranularity = si.dwAllocationGranularity;  
	}
	ShareMemory::~ShareMemory()
	{
	}

	bool ShareMemory::OpenShareMemory()
	{
		m_handle = g_winAPIs->OpenFileMappingW(FILE_MAP_ALL_ACCESS, 0, m_stName.c_str());
		if (!IS_VALID_HANDLE(m_handle))
		{
			APP_TRACE_LOG(LL_ERR, L"OpenFileMappingA failed with error: %u", g_winAPIs->GetLastError());

			m_handle = g_winAPIs->CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096, m_stName.c_str());
			if (!IS_VALID_HANDLE(m_handle))
			{
				APP_TRACE_LOG(LL_ERR, L"CreateFileMappingA failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			m_file = (BYTE*)g_winAPIs->MapViewOfFile(m_handle, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
			if (!m_file)
			{
				APP_TRACE_LOG(LL_ERR, L"MapViewOfFile failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			// set the file info
			m_shareMemInfo.nProcessCount++;
			memcpy(m_file, &m_shareMemInfo, sizeof(m_shareMemInfo));

			// set the address of buffer
			m_buf = m_file + sizeof(m_shareMemInfo);

			return true;
		}
		else
		{
			m_file = (BYTE*)g_winAPIs->MapViewOfFile(m_handle, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			if (!m_file)
			{
				APP_TRACE_LOG(LL_ERR, L"MapViewOfFile failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}

			// read the file info
			memcpy(&m_shareMemInfo, m_file, sizeof(m_shareMemInfo));
			m_shareMemInfo.nProcessCount++;
			memcpy(m_file, &m_shareMemInfo, sizeof(m_shareMemInfo));

			// set the address of the buffer
			m_buf = m_file + sizeof(m_shareMemInfo);

			return true;
		}
	}
	void ShareMemory::CloseShareMemory()
	{
		// Release all views of the file mapping
		for (const auto& view : m_mapViews)
		{
			g_winAPIs->UnmapViewOfFile(view.second);
		}
		m_mapViews.clear();

		if (m_handle)
		{
			memcpy(&m_shareMemInfo, m_file, sizeof(m_shareMemInfo));

			// If any client doesnt exist, delete it
			if (!(--m_shareMemInfo.nProcessCount))
				g_winAPIs->UnmapViewOfFile(m_buf);
			else
				memcpy(m_file, &m_shareMemInfo, sizeof(m_shareMemInfo));

			g_winAPIs->CloseHandle(m_handle);
			m_handle = nullptr;
		}

		m_buf = nullptr;
		m_file = nullptr;
	}

	bool ShareMemory::ReadMem(BYTE* data, size_t len)
	{
		if (!m_buf)
			return false;

		memcpy(data, m_buf, len);
		return true;
	}
	bool ShareMemory::WriteMem(BYTE* data, size_t len)
	{
		if (!m_buf)
			return false;

		memcpy(m_buf, data, len);
		return true;
	}

	uint32_t ShareMemory::GetSize() const
	{
		if (!m_handle)
			return 0;

		SECTION_BASIC_INFORMATION info{};
		if (!NT_SUCCESS(g_winAPIs->NtQuerySection(m_handle, SectionBasicInformation, &info, sizeof(info), nullptr)))
			return 0;

		return info.MaximumSize.LowPart;
	}

	bool ShareMemory::Lock(uint32_t nTimeoutMS)
	{
		if (!IS_VALID_HANDLE(m_hLockMtx))
		{
			const auto stLockName = m_stName.append(xorstr_(L"_lock"));

			m_hLockMtx = g_winAPIs->CreateMutexW(nullptr, FALSE, stLockName.c_str());
			if (!m_hLockMtx)
			{
				APP_TRACE_LOG(LL_ERR, L"CreateMutexA failed with error: %u", g_winAPIs->GetLastError());
				return false;
			}
		}

		return (g_winAPIs->WaitForSingleObject(m_hLockMtx, nTimeoutMS) == WAIT_OBJECT_0);
	}
	bool ShareMemory::Unlock()
	{
		return !!g_winAPIs->ReleaseMutex(m_hLockMtx);
	}


	LPBYTE ShareMemory::CreateView(DWORD dwOffset, DWORD dwLength)
	{
		// Create view with specified offset from the beginning of the file mapping and return pointer to the view
		DWORD dwBaseOffs = dwOffset - dwOffset % m_dwAllocGranularity;
		DWORD dwDiff = dwOffset - dwBaseOffs;

		auto pPtr = (LPBYTE)g_winAPIs->MapViewOfFile(m_handle, FILE_MAP_READ | FILE_MAP_WRITE, 0, dwBaseOffs, dwLength + dwDiff);
		m_mapViews[pPtr + dwDiff] = pPtr;

		return (pPtr + dwDiff);
	}
	void ShareMemory::DestroyView(LPBYTE pViewPtr)
	{
		// Release the view having specified starting pointer
		auto it = m_mapViews.find(pViewPtr);
		if (it != m_mapViews.end())
		{
			g_winAPIs->UnmapViewOfFile(it->second);
			m_mapViews.erase(it);
		}
	}
};
