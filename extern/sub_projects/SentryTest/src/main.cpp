#include <windows.h>
#include <stdio.h>
#include <string>
#define SENTRY_BUILD_SHARED
#include "sentry.h"

int main(void) 
{
	char szBuffer[MAX_PATH]{ '\0' };
	GetCurrentDirectoryA(MAX_PATH, szBuffer);
	std::string stHandler = szBuffer;
	stHandler += "\\NoMercy_Crash_Handler_x86.exe";
	
	sentry_options_t* options = sentry_options_new();
	
	sentry_options_set_dsn(options, "https://f9e580cff94f4443ba4f19f19ea9fd7f@sentry.nomercy.ac/2");
	sentry_options_set_handler_path(options, stHandler.c_str());
	sentry_options_set_database_path(options, "Dump");
	sentry_options_set_release(options, "standalone_test");
	sentry_options_set_traces_sample_rate(options, 1.0);
	sentry_options_set_debug(options, 1);
	sentry_options_set_logger(options, [](sentry_level_t level, const char* message, va_list args, void* userdata) {
		char szTmpBuffer[8192]{ '\0' };
		vsnprintf_s(szTmpBuffer, sizeof(szTmpBuffer), message, args);

		printf("[Sentry - %d]: %s\n", level, szTmpBuffer);
		OutputDebugStringA(szTmpBuffer);
	}, nullptr);

	sentry_init(options);

	sentry_capture_event(sentry_value_new_message_event(
		/*   level */ SENTRY_LEVEL_INFO,
		/*  logger */ "custom",
		/* message */ "It works!"
	));
	
	volatile int* a = (int*)(0);
	*a = 1;

	// make sure everything flushes
	sentry_close();

	while (true)
	{
		Sleep(100);
	}
	return 0;
}
