#include <iostream>
#include <string>
#include <fstream>
#include <filesystem>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void WriteFileContent(const std::string& szFileName, const std::string& szText)
{
	std::ofstream f(szFileName.c_str(), std::ofstream::out | std::ofstream::app);
	f << szText.c_str() << std::endl;
	f.close();
}

static RSA* generateKey(int num, unsigned long e)
{
#if OPENSSL_VERSION_NUMBER < 0x009080001
	return RSA_generate_key(num, e, NULL, NULL);
#else
	BIGNUM* eBig = BN_new();

	if (eBig == NULL)
	{
		return NULL;
	}

	if (!BN_set_word(eBig, e))
	{
		BN_free(eBig);
		return NULL;
	}

	RSA* result = RSA_new();

	if (result == NULL)
	{
		BN_free(eBig);
		return NULL;
	}

	if (RSA_generate_key_ex(result, num, eBig, NULL) < 0)
	{
		RSA_free(result);
		result = NULL;
	}

	BN_free(eBig);

	return result;
#endif
}

struct SDataBuffer
{
	char* data;
	long length;
};

static SDataBuffer toBuffer(BIO* bio)
{
	char* data;
	long length = BIO_get_mem_data(bio, &data);

	return SDataBuffer{ data, length };
}

bool Generate(int modulus, int exponent)
{
	if (modulus < 512)
	{
		printf("Expected modulus bit count bigger than 512.\n");
		return false;
	}

	if (exponent < 0)
	{
		printf("Expected positive exponent.\n");
		return false;
	}

	if ((exponent & 1) == 0)
	{
		printf("Expected odd exponent.\n");
		return false;
	}

	RSA* rsa = generateKey(modulus, (unsigned int)exponent);
	if (!rsa)
	{
		printf("Failed creating RSA context.\n");
		return false;
	}

	BIO* publicBio = BIO_new(BIO_s_mem());
	BIO* privateBio = BIO_new(BIO_s_mem());
	if (!publicBio || !privateBio)
	{
		if (publicBio)
			BIO_vfree(publicBio);

		if (privateBio)
			BIO_vfree(privateBio);

		RSA_free(rsa);

		printf("Failed to allocate OpenSSL buffers.\n");
		return false;
	}

	if (!PEM_write_bio_RSA_PUBKEY(publicBio, rsa))
	{
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		printf("Failed exporting public key.\n");
		return false;
	}

	if (!PEM_write_bio_RSAPrivateKey(privateBio, rsa, NULL, NULL, 0, NULL, NULL))
	{
		BIO_vfree(publicBio);
		BIO_vfree(privateBio);
		RSA_free(rsa);

		printf("Failed exporting private key.\n");
		return false;
	}

	const auto publicKey = toBuffer(publicBio);
	const auto privateKey = toBuffer(privateBio);

	if (std::filesystem::exists("public.key.backup"))
		std::filesystem::remove("public.key.backup");
	if (std::filesystem::exists("public.key"))
		std::filesystem::rename("public.key", "public.key.backup");

	if (std::filesystem::exists("private.key.backup"))
		std::filesystem::remove("private.key.backup");
	if (std::filesystem::exists("private.key"))
		std::filesystem::rename("private.key", "private.key.backup");

	WriteFileContent("public.key", std::string(publicKey.data, publicKey.length - 1));
	WriteFileContent("private.key", std::string(privateKey.data, privateKey.length - 1));

	BIO_vfree(publicBio);
	BIO_vfree(privateBio);
	RSA_free(rsa);

	return true;
}


int main(int argc, char** argv)
{
	int modulus = 2048;
	int exponent = 65537;

	if (argc == 3)
	{
		modulus = std::stoi(argv[1]);
		exponent = std::stoi(argv[2]);
	}

	printf("Modulus: %d Exponent: %d\n", modulus, exponent);

	if (Generate(modulus, exponent))
		printf("Success!\n");
	else
		printf("Failed!\n");

	std::system("PAUSE");
	return EXIT_SUCCESS;
}