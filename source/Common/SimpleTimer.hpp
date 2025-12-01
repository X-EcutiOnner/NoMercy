#pragma once
#include <chrono>

template <typename T>
class CStopWatch
{
	public:
		CStopWatch()
		{
			m_tStartPoint = std::chrono::high_resolution_clock::now();
		}
		~CStopWatch() = default;


		size_t diff()
		{
			return static_cast<size_t>(std::chrono::duration_cast<T>(std::chrono::high_resolution_clock::now() - m_tStartPoint).count());
		}

		void reset()
		{
			m_tStartPoint = std::chrono::high_resolution_clock::now();
		}

	private:
		std::chrono::time_point <std::chrono::high_resolution_clock> m_tStartPoint;
};
