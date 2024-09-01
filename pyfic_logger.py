"""
Functions 
- send event to log
- create discrepency report?
"""
import datetime
import os
import inspect
#from pyfic_utils import replace_backslashes

log_file_path = "C:/Users/Daniel/OneDrive/My_Documents/coding/git/File_integrity_checker/pyfic.log"

def append_log_event(level, description, associated_file=None, event_id=None):
    # Get the caller's info
    caller = inspect.currentframe().f_back
    func_name = caller.f_code.co_name
    line_number = caller.f_lineno

    # Create the log entry
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {level}"
    if event_id:
        log_entry += f" [Event ID: {event_id}]"
    log_entry += f" - {description}"
    if associated_file:
        log_entry += f" (File: {associated_file})"
    log_entry += f" | Function: {func_name}, Line: {line_number}"

    # Append the log entry to the file
    with open(log_file_path, 'a') as log_file:
        log_file.write(log_entry + '\n')

        








# Example usage
#log_file_path = "path/to/your/logfile.log"
#append_log_event(log_file_path, "INFO", "File hash checked", "/path/to/checked/file.txt", "HASH_CHECK_001")
#append_log_event(log_file_path, "WARNING", "File hash mismatch detected", "/path/to/changed/file.txt", "HASH_MISMATCH_001")


