from datetime import datetime


def custom_logger(message):
    log_file_path = "/var/ossec/logs/ar_custom_socket.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
        
