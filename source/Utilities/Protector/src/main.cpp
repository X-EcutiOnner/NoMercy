#include "pch.h"

// TODO: Anti-tamper
//	* Section encryption with dynamic keys on every run
//	* Obfuscate import dispatching
//	* Nanomites

extern bool rtti_obfuscate(const std::string& in, const std::string& out);
extern bool StripDebugInfo(const std::string& stFileName);

std::string gs_stInFile;
std::string gs_stPDBFile;
std::string gs_stOutFile;
std::uint32_t gs_nSeed = 0;

bool ProtectorMain()
{
	const auto bRttiObfuscated = rtti_obfuscate(gs_stInFile, gs_stOutFile);
	if (!bRttiObfuscated)
	{
		printf("RTTI obfuscate failed!\n");
		return false;
	}
	/*
	const auto bStripDebugInfo = StripDebugInfo(gs_stOutFile);
	if (!bStripDebugInfo)
	{
		printf("Strip debug info failed!\n");
		return false;
	}
	*/
	return true;
}

inline void ParseCommandLine(int argc, char** argv)
{
	cxxopts::Options options(argv[0], "");

	options.add_options()
		("i,in", "Input file", cxxopts::value<std::string>())
		("p,pdb", "PDB file", cxxopts::value<std::string>())
		("o,out", "Output file", cxxopts::value<std::string>())
		("s,seed", "Input key seed", cxxopts::value<std::uint32_t>())
	;

	try
	{
		auto result = options.parse(argc, argv);
		if (!result.count("in") || result.count("help"))
		{
			printf("%s\n", options.help().c_str());
			std::exit(EXIT_SUCCESS);
		}

		if (result.count("in"))
			gs_stInFile = result["in"].as<std::string>();

		printf("Input file: %s\n", gs_stInFile.c_str());

		if (result.count("pdb"))
			gs_stPDBFile = result["pdb"].as<std::string>();

		printf("PDB file: %s\n", gs_stPDBFile.c_str());

		if (result.count("out"))
			gs_stOutFile = result["out"].as<std::string>();
		else
		{
			std::filesystem::path p(gs_stInFile);
			gs_stOutFile = p.parent_path().string() + "\\" + "protected1_" + p.stem().string() + p.extension().string();
		}

		printf("Output file: %s\n", gs_stOutFile.c_str());

		if (result.count("seed"))
			gs_nSeed = result["seed"].as<std::uint32_t>();

		printf("Seed: %u\n", gs_nSeed);
	}
	catch (const cxxopts::exceptions::exception& ex)
	{
		const auto msg = fmt::format("IO Console parse exception: {}", ex.what()).c_str();
		assert(0 && !msg);
		return;
	}
	catch (const std::exception& ex)
	{
		const auto msg = fmt::format("IO System exception: {}", ex.what()).c_str();
		assert(0 && !msg);
		return;
	}
	catch (...)
	{
		assert(0 && !"IO Unhandled exception");
		return;
	}
}

int main(int argc, char* argv[])
{
	ParseCommandLine(argc, argv);

	if (!std::filesystem::exists(gs_stInFile))
	{
		printf("Input file: %s does not exist!\n", gs_stInFile.c_str());
		return EXIT_FAILURE;
	}
	if (gs_stInFile != gs_stOutFile && std::filesystem::exists(gs_stOutFile))
	{
		printf("Output file: %s already exist!\n", gs_stInFile.c_str());
		return EXIT_FAILURE;
	}
	if (!gs_stPDBFile.empty() && !std::filesystem::exists(gs_stPDBFile))
	{
		printf("PDB file: %s does not exist!\n", gs_stPDBFile.c_str());
		return EXIT_FAILURE;
	}

	const auto stInBackup = gs_stInFile + ".backup";
	if (std::filesystem::exists(stInBackup))
		std::filesystem::remove(stInBackup);

	std::filesystem::copy(gs_stInFile, stInBackup);

	auto fpInFile = msl::file_ptr(gs_stInFile, "rb");
	if (!fpInFile)
	{
		printf("Input file: %s could not open! Error: %d\n", gs_stInFile.c_str(), errno);
		return EXIT_FAILURE;
	}

	const auto vInBuffer = fpInFile.read();
	if (vInBuffer.empty())
	{
		printf("Input file: %s could not read! Error: %d\n", gs_stInFile.c_str(), errno);
		return EXIT_FAILURE;
	}

	fpInFile.close();

	const auto bRet = ProtectorMain();

	std::system("PAUSE");
	return bRet ? EXIT_SUCCESS : EXIT_FAILURE;
}
