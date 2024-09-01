""" 
PYFIC Python File Integrity Checker v 0.1. 

Core functionality 
- Gets hash value for critical system files
- stores hashes in an encrypted file
- Uses YAML configuration file 
- Cron Scheduling 
- Log file output

Future Goals 

Security 
- Secure key management (encrypting stored hashes)
- Integrity checks for the config file 
- Least privilege for scripts
Performance 
- Multithreading 
- Chunk reading (large files) 
SIEM Integration 
- Log format
- Filebeat for log shipping 
- Create Kibana Dashboard
Documentation 
- Write it as I go 

Long Term Goals 
- Realtime monitoring using watchdog library 
- Recursive directory monitoring
- Exclusion by file type
- File backup capabilities
- Alert System
- Various hashes (config file)
- Multi OS 

"""

from pyfic_monitor import FileMonitor

def main():
    monitor = FileMonitor()
    monitor.check_files()

if __name__ == "__main__":
    main()



    