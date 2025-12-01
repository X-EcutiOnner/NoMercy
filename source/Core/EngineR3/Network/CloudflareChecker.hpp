#include <iostream>
#include <vector>
#include <string>
#include <asio.hpp>
#include <stdexcept>
#include <optional>
#include <xorstr.hpp>

namespace CloudflareChecker
{
	// Cloudflare IP ranges
	const std::vector <std::string> cloudflare_ipv4_ranges =
	{
		xorstr_("173.245.48.0/20"),
		xorstr_("103.21.244.0/22"),
		xorstr_("103.22.200.0/22"),
		xorstr_("103.31.4.0/22"),
		xorstr_("141.101.64.0/18"),
		xorstr_("108.162.192.0/18"),
		xorstr_("190.93.240.0/20"),
		xorstr_("188.114.96.0/20"),
		xorstr_("197.234.240.0/22"),
		xorstr_("198.41.128.0/17"),
		xorstr_("162.158.0.0/15"),
		xorstr_("104.16.0.0/13"),
		xorstr_("104.24.0.0/14"),
		xorstr_("172.64.0.0/13"),
		xorstr_("131.0.72.0/22")
	};

	const std::vector <std::string> cloudflare_ipv6_ranges =
	{
		xorstr_("2400:cb00::/32"),
		xorstr_("2606:4700::/32"),
		xorstr_("2803:f800::/32"),
		xorstr_("2405:b500::/32"),
		xorstr_("2405:8100::/32"),
		xorstr_("2a06:98c0::/29"),
		xorstr_("2c0f:f248::/32")
	};

	// Utility function to split range into IP and mask
	std::optional <std::pair <std::string, uint8_t>> split_range(const std::string& range)
	{
		auto pos = range.find('/');
		if (pos == std::string::npos)
			return std::nullopt;

		std::string ip_str = range.substr(0, pos);
		uint8_t mask = static_cast<uint8_t>(std::stoi(range.substr(pos + 1)));

		return std::make_pair(ip_str, mask);
	}

	// Function to check if an IPv4 address is in a given range
	bool is_ipv4_in_range(const std::string& ip, const std::string& range)
	{
		auto split = split_range(range);
		if (!split)
			return false;

		asio::ip::address_v4 network = asio::ip::make_address_v4(split->first);
		uint8_t mask = split->second;

		asio::ip::address_v4 addr = asio::ip::make_address_v4(ip);
		asio::ip::address_v4::bytes_type network_bytes = network.to_bytes();
		asio::ip::address_v4::bytes_type addr_bytes = addr.to_bytes();

		uint32_t network_int = (network_bytes[0] << 24) | (network_bytes[1] << 16) | (network_bytes[2] << 8) | network_bytes[3];
		uint32_t addr_int = (addr_bytes[0] << 24) | (addr_bytes[1] << 16) | (addr_bytes[2] << 8) | addr_bytes[3];
		uint32_t mask_int = ~((1 << (32 - mask)) - 1);

		return (addr_int & mask_int) == (network_int & mask_int);
	}

	// Function to check if an IPv6 address is in a given range
	bool is_ipv6_in_range(const std::string& ip, const std::string& range)
	{
		auto split = split_range(range);
		if (!split)
			return false;

		asio::ip::address_v6 network = asio::ip::make_address_v6(split->first);
		uint8_t mask = split->second;

		asio::ip::address_v6 addr = asio::ip::make_address_v6(ip);
		asio::ip::address_v6::bytes_type network_bytes = network.to_bytes();
		asio::ip::address_v6::bytes_type addr_bytes = addr.to_bytes();

		for (int i = 0; i < 16; ++i)
		{
			int mask_bits = (i < mask / 8) ? 8 : (i == mask / 8) ? mask % 8 : 0;
			uint8_t mask_byte = (mask_bits == 8) ? 0xff : (mask_bits == 0) ? 0x00 : (0xff << (8 - mask_bits));

			if ((addr_bytes[i] & mask_byte) != (network_bytes[i] & mask_byte))
				return false;
		}
		return true;
	}

	// Function to check if an IP is in Cloudflare's IP ranges
	bool is_cloudflare_ip(const std::string& ip, std::string& err)
	{
		try
		{
			asio::ip::address addr = asio::ip::make_address(ip);

			if (addr.is_v4())
			{
				for (const auto& range : cloudflare_ipv4_ranges)
				{
					if (is_ipv4_in_range(ip, range))
						return true;
				}
			}
			else if (addr.is_v6())
			{
				for (const auto& range : cloudflare_ipv6_ranges)
				{
					if (is_ipv6_in_range(ip, range))
						return true;
				}
			}
		}
		catch (const std::exception& e)
		{
			err = e.what();
		}

		return false;
	}
}
