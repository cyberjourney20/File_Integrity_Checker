"""
Functions 
- Manage Config
    - Add file to config
    - Add other to config
- Hash functions
    - Hash target file 
    
"""

from cryptography.fernet import Fernet
import hashlib
import os 
import yaml
from datetime import datetime
from pyfic_logger import append_log_event

# Replaces double backslashes with single forward slash to work with windows paths.  
def replace_backslashes(path):
    return path.replace('\\', '/')

# Creates a SHA256 file hash for a specified file
def make_hash(file_path):
    print (f"\nAttemptiong to open: {file_path}") #DEBBUG CODE
    #create SHA-256 file hash
    sha256_hash = hashlib.sha256()
    # open file in binary for reading
    with open (file_path, "rb") as file:
        # for chunk in iter(lambda: file.read(4096), b""): # Alternate option uses iter and lambda instead of a while loop, 4KB chunks, b"" is an empty chunk instead of the break, setinal value in lambda function
        #read file in 64KB chunks to handle large files
        while True:
            data = file.read(65536)
            if not data: 
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()

# Creates a new hash for a specified file and compares it to a previously stored hash. Appends results to pyfic.log 
def check_file_integrity(hash_store_path, log_file_path):
    # Load the stored hash values
    stored_hashes = load_hash_file(hash_store_path)
    if not stored_hashes or 'file_hashes' not in stored_hashes:
        append_log_event("WARNING", "No stored hashes found", hash_store_path, "NO_HASHES_FOUND")
        return
    changes_detected = False
    for file_path, file_info in stored_hashes['file_hashes'].items():
        stored_hash = file_info['hash']
        # Check if the file still exists
        if not os.path.exists(file_path):
            append_log_event("WARNING", f"File no longer exists", file_path, "FILE_MISSING")
            changes_detected = True
            continue
        # Compute new hash
        try:
            new_hash = make_hash(file_path)
        except Exception as e:
            append_log_event("ERROR", f"Failed to compute hash: {str(e)}", file_path, "HASH_COMPUTE_ERROR")
            continue
        # Compare hashes
        if new_hash != stored_hash:
            append_log_event("WARNING", "File hash mismatch detected", file_path, "HASH_MISMATCH")
            changes_detected = True
        else:
            append_log_event("INFO", "File integrity verified", file_path, "INTEGRITY_OK")
    if not changes_detected:
        append_log_event("INFO", "All files integrity verified", event_id="ALL_FILES_OK")
    else:
        append_log_event("WARNING", "Changes detected in one or more files", event_id="CHANGES_DETECTED")
        
### Working With Config 
# includes place holder code for working with encrypted config file
def load_config(file_path, encryption_key=None):
    with open(file_path, 'r') as file:
        if encryption_key:
            f = Fernet(encryption_key)
            decrypted_data = f.decrypt(file.read())
            return yaml.safe_load(decrypted_data)
        else:
            return yaml.safe_load(file)

def write_config(config, file_path, encryption_key=None):
    with open(file_path, 'w', encoding='utf-8') as file:
        if encryption_key:
            f = Fernet(encryption_key)
            encrypted_data = f.encrypt(yaml.dump(config).encode())
            file.write(encrypted_data)
        else:
            yaml.dump(config, file, default_flow_style=False, allow_unicode=True)

def add_monitored_file(config, file_path):
    if 'monitor_list' not in config:
        config['monitor_list'] = {}
    if 'included_files' not in config['monitor_list'] or config['monitor_list']['included_files'] is None:
        config['monitor_list']['included_files'] = []
    
    # Ensure the file path is not already in the list
    if file_path not in config['monitor_list']['included_files']:
        config['monitor_list']['included_files'].append(file_path)
    #write_config(working_config, config_path)
    append_log_event('INFO', 'Added monitored file', file_path, '001_HASH_ADD')

### Working with Hash Store 
def load_hash_file(hash_file_path):
    try:
        with open(hash_file_path, 'r') as file:
            return yaml.safe_load(file) or {}
    except FileNotFoundError:
        return {}

def save_hash_file(data, hash_file_path):
    print(f"Saving data: {data}")  # Debug print
    with open(hash_file_path, 'w') as file:
        yaml.dump(data, file, default_flow_style=False)

def add_file_hash(data, hash_file_path, new_hash):
    print(f"Input data: {data}")  # Debug print
    if data is None:
        data = {}
    if 'file_hashes' not in data or data['file_hashes'] is None:
        data['file_hashes'] = {}
    data['file_hashes'][hash_file_path] = {
        'hash': new_hash,
        'date_created': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'size': os.path.getsize(hash_file_path)
    }
    print(f"Updated data: {data}")  # Debug print
    return data

def update_file_hashes(config_path, store_path, log_path):
    # Load configuration
    with open(config_path, 'r') as config_file:
        config = yaml.safe_load(config_file)
    # Initialize list to store file paths
    files_to_monitor = []
    # Extract file paths from config
    if 'monitor_list' in config:
        monitor_list = config['monitor_list'] 
        # Add individual files
        if 'included_files' in monitor_list:
            files_to_monitor.extend(monitor_list['included_files']) 
        # Add files from included directories
        #if 'included_directory' in monitor_list:
        #    for directory in monitor_list['included_directory']:
        #        if directory.endswith('*'):
        #            directory = directory[:-1]  # Remove the trailing *
        #            files_to_monitor.extend([os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
        #        else:
        #            files_to_monitor.extend([os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))])
        # Add files from recursively included directories
        #if 'included_directory_recursive' in monitor_list:
        #    for directory in monitor_list['included_directory_recursive']:
        #        for root, _, files in os.walk(directory):
        #            files_to_monitor.extend([os.path.join(root, f) for f in files])
    # Load existing hash store or create new one
    hash_store = load_hash_file(store_path)
    if 'file_hashes' not in hash_store:
        hash_store['file_hashes'] = {}
    # Compute and store hashes
    for file_path in files_to_monitor:
        try:
            file_hash = make_hash(file_path)
            hash_store['file_hashes'][file_path] = {
                'hash': file_hash,
                'last_checked': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'size': os.path.getsize(file_path)
            }
            append_log_event("INFO", f"Hash updated for file", file_path, "HASH_UPDATED")
        except Exception as e:
            append_log_event("ERROR", f"Failed to compute hash: {str(e)}", file_path, "HASH_COMPUTE_ERROR")
    # Save updated hash store
    save_hash_file(hash_store, store_path)
    append_log_event("INFO", f"Hash store updated with {len(files_to_monitor)} files", event_id="HASH_STORE_UPDATED")


# Working with Hash Store Usage
# hash_data = load_hash_file('file_hashes.yaml')
# update_file_hash(hash_data, '/path/to/checked/file.txt', 'new_hash_value')
# save_hash_file(hash_data, 'file_hashes.yaml')
