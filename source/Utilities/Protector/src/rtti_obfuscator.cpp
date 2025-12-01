#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <random>
#include <time.h>
#include <cstdlib>
#include <unordered_set>
#include <regex>
#include <filesystem>

std::unordered_set <std::string> usedTypeNames;

std::string getRandomString(const int len)
{
	std::string s;
	s.resize(len);

	for (auto i = 0; i < len; ++i)
	{
		// just pick a random byte
		s[i] = rand() % 0xff;
	}

	s[len] = 0;	
	return s;
}

namespace std
{
	template<class Iterator, class Settings, class StringType, class SingleArg>
	std::basic_string<StringType> regex_replace(Iterator iterStart, Iterator iterFinish, const std::basic_regex<StringType,
		Settings>& expressions, SingleArg sArg)
	{
		std::basic_string<StringType> sBuffer;

		typename std::match_results<Iterator>::difference_type lastPos = 0;
		auto lastPosEnd = iterStart;

		auto regexp_callback = [&](const std::match_results<Iterator>& m)
		{
			auto pos = m.position(0);
			auto difference = pos - lastPos;

			auto start = lastPosEnd;
			std::advance(start, difference);

			sBuffer.append(lastPosEnd, start);
			sBuffer.append(sArg(m));

			auto len = m.length(0);

			lastPos = pos + len;

			lastPosEnd = start;
			std::advance(lastPosEnd, len);
		};

		std::sregex_iterator start(iterStart, iterFinish, expressions), finish;
		std::for_each(start, finish, regexp_callback);

		sBuffer.append(lastPosEnd, iterFinish);

		return sBuffer;
	}

	template<class Settings, class StringType, class SingleArg>
	std::string regex_replace(const std::string& sBuffer,
		const std::basic_regex<StringType, Settings>& expressions, SingleArg sArg)
	{
		auto begin = sBuffer.cbegin();
		auto end = sBuffer.cend();
		return regex_replace(begin, end, expressions, sArg);
	}
}

bool rtti_obfuscate(const std::string& in, const std::string& out)
{
	srand(static_cast<unsigned int>(std::time(nullptr)));

	try
	{
		std::ifstream fs(in, std::fstream::binary);
		if (fs.fail())
		{
			throw std::exception("Could not open source binary");
		}

		// read file contents
		std::stringstream ss;
		ss << fs.rdbuf();
		auto contents = ss.str();

		std::regex reg(R"(\.(\?AV|PEAV)(.+?)@@\0)");

		// replace RTTI types
		contents = std::regex_replace(contents, reg, [&](const std::smatch& m) {
			auto prefix = m[1].str();
			auto typeName = m[2].str();

			auto length = 1 + prefix.size() + typeName.size() + 2;

			// max length of the new type name
			auto maxNewLength = 3UL;

			// get a new random name untill we have one we never used before
			std::string newTypeName;
			do
			{
				newTypeName = getRandomString(length);
				if (newTypeName.size() > maxNewLength)
				{
					memset(const_cast<char*>(newTypeName.data()) + maxNewLength, 0, length - maxNewLength);
				}

			} while (usedTypeNames.find(newTypeName) != usedTypeNames.end());

			usedTypeNames.emplace(newTypeName);

			return newTypeName + '\0';
		});

		// generate output path
		std::ofstream os(out, std::ofstream::trunc | std::ofstream::binary);
		if (!os.write(contents.data(), contents.size()))
		{
			throw std::exception((std::string("Unable to write to file ") + out).c_str());
		}

		printf("Successfully obfuscated RTTI information.\n");
		return true;
	}
	catch (std::exception& e)
	{
		printf("RTTI obfuscator exception: %s\n", e.what());
		return false;
	}
}
