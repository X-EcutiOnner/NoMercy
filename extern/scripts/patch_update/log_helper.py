import os
import datetime
import sentry_sdk
import config_data

LOG_FILENAME = "PatchUploader.log"
ERROR_LOG = "[ERROR]"
INFO_LOG = "[INFO]"

def get_datetime():
    sysTime = datetime.datetime.now()

    # Extract the individual components from sysTime
    hour = sysTime.hour
    minute = sysTime.minute
    second = sysTime.second
    day = sysTime.day
    month = sysTime.month
    year = sysTime.year

    # Create a formatted string representation of the date and time
    formatted_datetime = "{:02d}-{:02d}-{:04d} {:02d}:{:02d}:{:02d}".format(day, month, year, hour, minute, second)
    return formatted_datetime

def file_log(log_file, log_message):
    with open(log_file, "a") as file:
        buffer = f"{get_datetime()} :: {log_message}\n"
        file.write(buffer)
        
def console_log(log_message):
    print(f"{get_datetime()} :: {log_message}")
    
def sentry_log(log_message):
    if config_data.sentry_ready:
        sentry_sdk.capture_message(log_message)
    
def log_ex(level, log_message):
    if level == ERROR_LOG:
        log_message = f"{ERROR_LOG} :: {log_message}"
    elif level == INFO_LOG:
        log_message = f"{INFO_LOG} :: {log_message}"
    else:
        sentry_log(f"Invalid log level '{level}'")
        return
    
    file_log(LOG_FILENAME, log_message)
    console_log(log_message)
    if level == ERROR_LOG:
        sentry_log(log_message)

def log(level, log_message, *args):
    log_ex(level, log_message % args)
