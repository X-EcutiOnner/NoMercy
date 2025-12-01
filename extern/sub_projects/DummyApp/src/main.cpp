#include <windows.h>
#include <iostream>
#include <thread>
#include <chrono>
 
int main()
{
	static uint64_t i = 0;
	for (;;)
	{
		std::cout << "[" << i++ << "] Working..." << std::endl;
		std::this_thread::sleep_for(std::chrono::seconds(1));
	}

	return EXIT_SUCCESS;
}