#pragma once

namespace NoMercy
{
	class CMTRandom
	{
		static const int n = 624, m = 397;

	public:
		CMTRandom(uint32_t s);
		uint32_t next();

	protected:
		uint32_t twiddle(uint32_t, uint32_t);
		void gen_state();
		void seed(uint32_t);

	private:
		uint32_t state[n];
		int p;
		bool init;
	};
};
