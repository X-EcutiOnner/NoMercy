#pragma once
#include "CertificateInfoBase.hpp"
#include <memory>

namespace NoMercyCore
{
	class SignerInfo : public CertificateInfoBase
	{
	public:
		using SignerInfoPtr = std::shared_ptr <SignerInfo>;

		SignerInfo() { };
		virtual ~SignerInfo() { };
	};
};
