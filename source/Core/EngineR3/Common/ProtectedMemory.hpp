#pragma once

namespace NoMercy
{
	class DataBuffer
	{
	public:
		DataBuffer();
		DataBuffer(const size_t size);
		DataBuffer(const void* ptr, const size_t size);
		DataBuffer(const DataBuffer& data, uint32_t pos, uint32_t size);
		DataBuffer(const DataBuffer& right);
		virtual ~DataBuffer();

		const DataBuffer& operator=(const DataBuffer& right);
		bool  operator==(const DataBuffer& right) const;
		bool  operator!=(const DataBuffer& right) const;
		byte& operator[](const size_t offset);
		DataBuffer operator()(int begin, int end) const;

		void* get_ptr() const;
		byte* get_ptr_bytes() const;
		template <typename T> T* get() { return reinterpret_cast<T*>(get_ptr()); }
		template <typename T> const T* get() const { return reinterpret_cast<const T*>(get_ptr()); }

		size_t get_size() const;

		bool empty() const;

		void reset();
		void fill(const byte v = 0);
		bool resize(const size_t size);
		bool replace(const void* ptr, const size_t size);
		bool replace(const DataBuffer& right);
		bool match(const void* ptr, const size_t size) const;
		size_t find(const void* ptr, const size_t size) const;
		DataBuffer till(const void* ptr, const size_t size) const;
		DataBuffer slice(int begin, int end) const;

		bool append(const void* ptr, const size_t size);
		bool append(const DataBuffer& right);

		std::string  to_string_A() const;
		std::wstring to_string_W() const;

		bool save_to_file(const std::string& file_path);
		bool save_to_file(const std::wstring& file_path);

		void encrypt();
		void decrypt();

	protected:
		bool create(void* ptr, const size_t size, const bool clean = true);
		bool destroy();

	private:
		void*	m_ptr;
		size_t	m_size;
		uint8_t m_key;
		bool	m_crypted;
	};
}
