import json
import socket
from struct import pack, unpack
from multiprocessing import Process
from wazuh.core import common
from os import remove, path as os_path,environ
from datetime import datetime
from wazuh.core.exception import WazuhError

class WazuhInternalError(Exception):
    pass

_ = None
rec_error = None
rec_data = None

def custom_logger(message):
    log_file_path = "/var/ossec/logs/ar_custom_socket.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))
        
def env_logger(message):
    log_file_path = "/var/ossec/logs/ar_custom_socket.log"
    timestamp = datetime.now().strftime("%Y/%m/%d %H:%M:%S.%f")[:-3]
    log_entry = f"{timestamp} {message}\n"
    
    with open(log_file_path, 'a') as file:
        file.write(str(log_entry))

class MySocket:
    MAX_SIZE = 65536

    def __init__(self, path):
        self.path = path
        self._connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __enter__(self):
        return self

    def _connect(self):
        try:
            self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self.s.connect(self.path)
        except FileNotFoundError as e:
            custom_logger(f"File does not exist ERROR: {e}")
        except ConnectionRefusedError as e:
            custom_logger(f"Connection refused ERROR: {e}")
        except Exception as e:
            custom_logger(f"ERROR: {e}")

    def close(self):
        self.s.close()

    def send(self, msg_bytes, header_format="<I"):
        if not isinstance(msg_bytes, bytes):
            custom_logger("Type must be bytes")
            return

        try:
            sent = self.s.send(pack(header_format, len(msg_bytes)) + msg_bytes)
            if sent == 0:
                custom_logger("ERROR: Number of sent bytes is 0")
            return sent
        except Exception as e:
            custom_logger(f"ERROR: {e}")

    def receive(self, header_format="<I", header_size=4):
        try:
            size = unpack(header_format, self.s.recv(header_size, socket.MSG_WAITALL))[0]
            return self.s.recv(size, socket.MSG_WAITALL)
        except Exception as e:
            custom_logger(f"ERROR: {e}")

def handle_agent(agent_id,component,configuration,response_queue):
    
    dest_socket = common.REMOTED_SOCKET
    GETCONFIG_COMMAND = "getconfig"

    msg = f"{str(agent_id).zfill(3)} {component} {GETCONFIG_COMMAND} {configuration}"

    custom_logger(f"Encoded MSG for agent {agent_id}: {msg.encode()}")
    env = environ.get('TEST_ENV')
    env_logger(f"env logs : {env}")

    try:
        with MySocket(dest_socket) as s:
            custom_logger(f"Connected to the socket: {dest_socket}")

            # Send message
            s.send(msg_bytes=msg.encode())
            custom_logger("-------------- SEND THE MSG ----------------")

            # Receive response
            rec_msg_ok, rec_msg = s.receive().decode().split(" ", 1)
            custom_logger("--------------- MSG RECV SUCCESSFULLY -----------------")
            custom_logger(f"rec_msg_ok: {rec_msg_ok} | rec_msg: {rec_msg}")

            response_queue.put((agent_id, rec_msg_ok, rec_msg))
    except WazuhInternalError as e:
        custom_logger(f"WazuhInternalError {e}")
        response_queue.put((agent_id, "error", f"WazuhInternalError{e}"))
    except Exception as unhandled_exc:
        custom_logger(f"ERROR: {unhandled_exc}")
        response_queue.put((agent_id, "error", str(unhandled_exc)))

def process_agents(agent_id, component, configuration, timeout=1):
    from multiprocessing import Queue

    processes = []
    response_queue = Queue()

    
    p = Process(target=handle_agent, args=(agent_id,component, configuration, response_queue))
    custom_logger(f"the prosses was initalize : {p}")
    processes.append(p)

    custom_logger(f"add the prosses inthe list : {processes}")

    p.start()

    for p in processes:
        p.join(timeout=timeout)
        if p.is_alive():
            custom_logger("prosses is live")
            p.terminate()
            custom_logger("prosse termineted")
            response_queue.put((p.name, "err", "Response timeout"))
            custom_logger("add the responce of the timoute in code")

    responses = []
    while not response_queue.empty():
        responses.append(response_queue.get())
    custom_logger(f"the responce of the prosses anget : {responses}")
    
    if len(responses) == 0 :
        rec_error = "ok"
        rec_data = "Response timeout"
        
    elif len(responses) > 0:
        for item in responses:
        # Unpack the tuple
            _, rec_error, rec_data = item 
        custom_logger(f"unpack the data from list id : {_}, rec_error : {rec_error}, rec_data : {rec_data}")
    else:
        WazuhError(3036)
    
    if rec_error == 'ok' or rec_error == 0:
        data = json.loads(rec_data) if isinstance(rec_data, str) else rec_data

        # Include password if auth->use_password enabled and authd.pass file exists
        if data.get('auth', {}).get('use_password') == 'yes':
            try:
                with open(os_path.join(common.WAZUH_PATH, "etc", "authd.pass"), 'r') as f:
                    data['authd.pass'] = f.read().rstrip()
            except IOError:
                pass
        custom_logger(f"prossec the agetn funcion return data is : {data}")
        return data
    else:
        raise WazuhError(1117 if "No such file or directory" in rec_data or "Cannot send request" in rec_data else 1116,
                         extra_message=f'{component}:{configuration}')