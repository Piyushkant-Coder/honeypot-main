#Libraries
import logging
from logging.handlers import RotatingFileHandler
import paramiko
import getpass
from paramiko.ssh_exception import PasswordRequiredException, SSHException
import socket
import threading

#Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-OpenSSH_7.4"

def load_host_key(path='server.key'):
    """Try to load the host private key. If it's encrypted prompt for a passphrase."""
    try:
        return paramiko.RSAKey.from_private_key_file(path)
    except PasswordRequiredException:
        pw = getpass.getpass("Enter private key passphrase: ")
        return paramiko.RSAKey.from_private_key_file(path, password=pw)
    except SSHException:
        # Try Ed25519 (or other types) as a fallback
        try:
            return paramiko.Ed25519Key.from_private_key_file(path)
        except PasswordRequiredException:
            pw = getpass.getpass("Enter private key passphrase: ")
            return paramiko.Ed25519Key.from_private_key_file(path, password=pw)
        except Exception as e:
            print("Failed to load host key:", e)
            raise

# Load host key (will prompt if the key is passphrase-protected)
host_key = load_host_key('server.key')

#Loggers & Logging Files
funnel_logger = logging.getLogger('funnellogger')
funnel_logger.setLevel(logging.INFO)
funnel_handler = RotatingFileHandler('audits.log', maxBytes=2000, backupCount=5)
funnel_handler.setFormatter(logging_format)
funnel_logger.addHandler(funnel_handler)

creds_logger = logging.getLogger('CredsLogger')
creds_logger.setLevel(logging.INFO)
creds_handler = RotatingFileHandler('cmd_audits.log', maxBytes=2000, backupCount=5)
creds_handler.setFormatter(logging_format)
creds_logger.addHandler(creds_handler)

#Emulated Shell
def emulated_shell(channel, client_ip):
    greeting = b"Welcome to the SSH Honeypot!\r\n"
    prompt = b"honeypot_user@honeypot:~$ "
    channel.send(greeting + prompt)

    command_bytes = bytearray()

    while True:
        try:
            char = channel.recv(1)
        except Exception:
            break

        if not char:
            try:
                channel.close()
            except Exception:
                pass
            break

        # Backspace (DEL, 0x7f): remove last byte and update client display
        if char == b'\x7f':
            if len(command_bytes) > 0:
                command_bytes = command_bytes[:-1]
                # move cursor back, overwrite with space, move back again
                channel.send(b'\b \b')
            continue

        # If an escape sequence starts (e.g. arrow keys, ctrl sequences), consume & ignore it
        if char == b'\x1b':  # ESC
            # read rest of escape sequence (very basic)
            # typical sequences start with '[' then some bytes and end with a letter
            try:
                nxt = channel.recv(1)
                if nxt == b'[':
                    # consume until alphabetic final byte
                    seq = b''
                    while True:
                        c = channel.recv(1)
                        seq += c
                        if not c:
                            break
                        if 65 <= c[0] <= 122:  # ASCII letter end of sequence
                            break
                # ignore escape sequence entirely
            except Exception:
                pass
            continue

        # If char is newline or carriage return -> process command
        if char in (b'\r', b'\n'):
            # sanitize: only keep printable ascii from the buffer
            try:
                decoded = command_bytes.decode('utf-8', errors='ignore').strip()
            except Exception:
                decoded = ''
            # log the command with client IP
            creds_logger.info(f"{client_ip} - CMD: {decoded}")

            # respond to known commands
            if decoded == 'exit':
                channel.send(b"\r\n Goodbye!\r\n")
                try:
                    channel.close()
                except Exception:
                    pass
                break
            elif decoded == 'pwd':
                response = b"\r\n/home/honeypot\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")
            elif decoded == 'whoami':
                response = b"\r\nhoneypot_user\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")
            elif decoded == 'ls':
                response = b"\r\ndocument.txt  secrets.txt  data.log\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")
            elif decoded == 'cat secrets.txt':
                response = b"\r\nTop Secret Data: [REDACTED]\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")
            elif decoded == '':
                response = b"\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")
            else:
                response = b"\r\nCommand not found\r\n"
                creds_logger.info(f"{client_ip} - Response: {decoded}")

            # send response and prompt
            channel.send(response + prompt)

            # reset buffer
            command_bytes = bytearray()
            continue

        # For normal printable characters (space..~), append and echo back
        b0 = char[0]
        if 32 <= b0 <= 126:  # printable ASCII
            command_bytes += char
            # echo back the character so client display looks correct
            try:
                channel.send(char)
            except Exception:
                pass
            continue

        # ignore other control characters
        # (you can add handling for TAB etc. if desired)
        continue


   
#SSH Server + Sockets
class Server(paramiko.ServerInterface):

    def __init__(self, client_ip, input_username=None, input_password=None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_password = input_password
    def check_channel_request(self, kind: str, chanid: int) -> int:
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auth(self):
        return 'password'

    def check_auth_password(self, username, password):
        """Authenticate using configured credentials if provided; otherwise allow any password."""
        funnel_logger.info(f"{self.client_ip} - Attempted login with Username: '{username}' and Password: '{password}'") 
        creds_logger.info(f"{self.client_ip}, {username},{password}")
        if self.input_username is not None and self.input_password is not None:
            if username == self.input_username and password == self.input_password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        # accept any exec for now
        return True

def client_handle(client, addr, username, password):
    client_ip = addr[0]
    print(f"{client_ip} has connected to the server.")

    try:

        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip = client_ip, input_username=username, input_password=password)

        transport.add_server_key(host_key)

        transport.start_server(server=server)
        
        channel = transport.accept(100)
        if channel is None:
            print("No channel was opened")
        standard_banner = b"Welcome to Ubuntu 22.04 LTS (GNU/Linux 5.15.0-1019-azure x86_64)\r\n\r\n"

        channel.send(standard_banner)
        emulated_shell(channel, client_ip=client_ip)

    except Exception as error:
        print(error)
        print("!!! Error !!!")
    finally:
        try:
            transport.close()
        except Exception as error:
            print("!!! Error !!!")
        client.close()

#Provision SSH-based Honeypot

def honeypot(address, port, username, password):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH Server is listening on port {port}.")

    while True:
        try:

            client,addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print(error)

honeypot('127.0.0.1', 2223, username=None, password=None)
