#include "../PCH.hpp"
#include "../Index.hpp"
#include "../Application.hpp"
#include "ProtectedMemory.hpp"

namespace NoMercy
{
	DataBuffer::DataBuffer() :
		m_ptr(nullptr), m_size(0), m_key((uint8_t)(rand() % 255)), m_crypted(false)
	{
		this->create(nullptr, 0);
	}
	DataBuffer::DataBuffer(const size_t size) :
		m_ptr(nullptr), m_size(0), m_key((uint8_t)(rand() % 255)), m_crypted(false)
	{
		this->create(nullptr, size);
	}
	DataBuffer::DataBuffer(const void* ptr, const size_t size) :
		m_ptr(nullptr), m_size(0), m_key((uint8_t)(rand() % 255)), m_crypted(false)
	{
		this->replace(ptr, size);
	}
	DataBuffer::DataBuffer(const DataBuffer& new_data, uint32_t pos, uint32_t size) :
		m_ptr(nullptr), m_size(0), m_key((uint8_t)(rand() % 255)), m_crypted(false)
	{
		this->replace(new_data.get_ptr_bytes() + pos, size);
	}
	DataBuffer::DataBuffer(const DataBuffer& right) :
		m_ptr(nullptr), m_size(0), m_key((uint8_t)(rand() % 255)), m_crypted(false)
	{
		*this = right;
	}

	DataBuffer::~DataBuffer()
	{
		this->destroy();
	}

	const DataBuffer& DataBuffer::operator=(const DataBuffer& right)
	{
		if (*this != right)
		{
			if (this->create(nullptr, right.m_size))
			{
				if (right.m_ptr != nullptr)
				{
					memcpy_s(m_ptr, m_size, right.m_ptr, right.m_size);
				}
			}
		}

		return *this;
	}
	bool DataBuffer::operator==(const DataBuffer& right) const
	{
		if (m_size != right.m_size)
		{
			return false;
		}

		return memcmp(m_ptr, right.m_ptr, m_size) == 0;
	}
	bool DataBuffer::operator!=(const DataBuffer& right) const
	{
		return !(*this == right);
	}
	byte& DataBuffer::operator[](const size_t offset)
	{
		if (m_ptr == nullptr)
		{
			throw std::runtime_error(static_cast<const char*>(xorstr_("invalid pointer")));
		}

		if (m_size == 0 || offset >= m_size)
		{
			throw std::out_of_range(static_cast<const char*>(xorstr_("invalid size or offset")));
		}

		return static_cast<byte*>(m_ptr)[offset];
	}
	DataBuffer DataBuffer::operator()(int begin, int end) const
	{
		return this->slice(begin, end);
	}
	
	size_t DataBuffer::find(const void* ptr, const size_t size) const
	{
		auto result = static_cast<size_t>(-1);

		if (m_ptr == nullptr || m_size == 0 || ptr == nullptr || size == 0 || m_size < size)
		{
			return result;
		}

		const auto ptr_bytes = this->get_ptr_bytes();

		for (size_t i = 0; i <= m_size - size; i++)
		{
			if (memcmp(reinterpret_cast<const void*>(ptr_bytes + i), ptr, size) == 0)
			{
				result = i;
				break;
			}
		}

		return result;
	}
	
	bool DataBuffer::match(const void* ptr, const size_t size) const
	{
		return this->find(ptr, size) != -1;
	}

	DataBuffer DataBuffer::till(const void* ptr, const size_t size) const
	{
		DataBuffer result;

		size_t offset = this->find(ptr, size);
		if (offset > 0)
		{
			result.create(m_ptr, offset);
		}

		return result;
	}

	DataBuffer DataBuffer::slice(int begin, int end) const
	{
		DataBuffer result;

		if (m_ptr == nullptr || m_size == 0)
		{
			return result;
		}

		if (begin < 0)
		{
			begin = int(m_size) + begin;
		}

		if (end < 0)
		{
			end = int(m_size) + end;
		}

		if (begin < 0 || end < 0 || begin > int(m_size) || end > int(m_size) || begin > end)
		{
			return result;
		}

		int size = end - begin;

		if (size <= 0 || size > int(m_size))
		{
			return result;
		}

		result.create(this->get_ptr_bytes() + begin, size);

		return result;
	}

	byte* DataBuffer::get_ptr_bytes() const
	{
		return static_cast<byte*>(m_ptr);
	}

	void* DataBuffer::get_ptr() const
	{
		return m_ptr;
	}

	size_t DataBuffer::get_size() const
	{
		return m_size;
	}

	bool DataBuffer::create(void* ptr, const size_t size, const bool clean)
	{
		if (clean || size == 0)
		{
			this->destroy();
		}

		if (size == 0)
		{
			return false;
		}

		if (clean)
		{
			m_ptr = std::calloc(m_size = size, 1);
		}
		else
		{
			m_ptr = std::realloc(ptr, m_size = size);
		}

		if (m_ptr == nullptr)
		{
			throw std::bad_alloc();
		}

		if (ptr == nullptr)
		{
			memset(m_ptr, 0, m_size);
		}
		else if (clean)
		{
			memcpy_s(m_ptr, m_size, ptr, size);
		}

		return true;
	}

	bool DataBuffer::destroy()
	{
		if (m_ptr != nullptr)
		{
			std::free(m_ptr);
		}

		m_ptr = nullptr;
		m_size = 0;

		return true;
	}

	void DataBuffer::reset()
	{
		this->destroy();
	}

	void DataBuffer::fill(const byte v)
	{
		if (m_ptr != nullptr && m_size != 0)
		{
			memset(m_ptr, v, m_size);
		}
	}

	bool DataBuffer::resize(const size_t size)
	{
		if (size == m_size)
		{
			return true;
		}

		return this->create(m_ptr, size, false);
	}

	bool DataBuffer::replace(const void* ptr, const size_t size)
	{
		if (this->create(nullptr, size))
		{
			if (ptr != nullptr)
			{
				memcpy_s(m_ptr, m_size, ptr, size);
			}
		}

		return true;
	}

	bool DataBuffer::replace(const DataBuffer& right)
	{
		return this->replace(right.get_ptr(), right.get_size());
	}

	bool DataBuffer::empty() const
	{
		return m_ptr == nullptr || m_size == 0;
	}

	bool DataBuffer::append(const void* ptr, const size_t size)
	{
		if (ptr == nullptr || size == 0)
		{
			return false;
		}

		const size_t prev_size = m_size;

		this->resize(m_size + size);

		memcpy_s(this->get_ptr_bytes() + prev_size, size, ptr, size);

		return true;
	}

	bool DataBuffer::append(const DataBuffer& right)
	{
		return this->append(right.get_ptr(), right.get_size());
	}

	std::string DataBuffer::to_string_A() const
	{
		return std::string(reinterpret_cast<const char*>(get_ptr()), m_size / sizeof(char));
	}

	std::wstring DataBuffer::to_string_W() const
	{
		return std::wstring(reinterpret_cast<const wchar_t*>(get_ptr()), m_size / sizeof(wchar_t));
	}

	bool DataBuffer::save_to_file(const std::wstring& file_path)
	{
		if (file_path.empty())
			return false;

		bool result = true;

		auto fp = msl::file_ptr(file_path, xorstr_(L"wb"));
		if (!fp)
			return false;

		fp.write(get_ptr(), m_size);
		fp.close();
		return true;
	}

	bool DataBuffer::save_to_file(const std::string& file_path)
	{
		return this->save_to_file(stdext::to_wide(file_path));
	}

	void DataBuffer::encrypt()
	{
		if (!m_crypted)
		{
			auto buffer = reinterpret_cast<uint8_t*>(m_ptr);
			
			for (uint8_t i = 0; i < m_size; i++)
			{
				buffer[i] ^= m_key;
			}

			m_crypted = true;
		}
	}

	void DataBuffer::decrypt()
	{
		if (m_crypted)
		{
			auto buffer = reinterpret_cast<uint8_t*>(m_ptr);
			
			for (uint8_t i = 0; i < m_size; i++)
			{
				buffer[i] ^= m_key;
			}

			 m_crypted = false;
		}
	}
};
