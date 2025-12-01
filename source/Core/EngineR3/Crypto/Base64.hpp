#pragma once
#include <string>
#include <vector>

namespace NoMercy
{
	class CBase64
	{
		using binary_type = std::vector <std::uint8_t>;

	public:
		static std::string encode(const std::string& data);
		static std::string encode(const binary_type& data);
		static std::string encode(const std::uint8_t* data, std::size_t len);
		static std::string url_encode(const std::string& in);

		static std::string decode(const std::string& input);
		static binary_type decode_binary(const std::string& input);

		template <std::size_t array_size>
		static std::string array_to_base64(const std::array <std::uint8_t, array_size>& data);

		template <class type>
		static type base64_to_array(const std::string& input);
	};

	template <std::size_t array_size>
	std::string CBase64::array_to_base64(const std::array <std::uint8_t, array_size>& data)
	{
		return encode( data.data(), data.size() );
	}

	template <class type>
	type CBase64::base64_to_array(const std::string& input)
	{
		type key;
		auto data = decode_binary(input);
		std::copy_n(std::make_move_iterator(data.begin()), key.size(), key.begin());
		return key;
	}
}