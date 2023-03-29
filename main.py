import os
import time
import random
import select
import socket
import struct
import readline

from threading import Thread
from netifaces import interfaces
from traceback import format_exc
from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler


__version__ = "1.2.1"
_ = readline
tunnels = {}
log_stream = False
socks_proxy_password = "password"


class Tunnel:
    def __init__(self, vpn_server, name=None, username=None, password=None):
        self._id = random.randint(0, 99999)
        self.name = f"pptp-vpn-proxy-{self._id}" if name is None else name
        self.server = vpn_server
        self.username, self.password = username, password
        self._tunnel = self.tunnel_text
        with open(f"/etc/ppp/peers/{self.name}", "w") as file:
            file.write(self._tunnel)

    @property
    def tunnel_text(self):
        return f'''
            pty "pptp {self.server} --nolaunchpppd --debug"
            name {self.username}
            password {self.password}
            remotename PP{self.name}{self._id}
            require-mppe-128
            require-mschap-v2
            refuse-eap
            refuse-pap
            refuse-chap
            refuse-mschap
            noauth
            debug
            maxfail 0
            ifname {self.name}
        '''

    def on(self):
        os.system(f'pon {self.name}')

    def off(self):
        os.system(f'poff {self.name}')

    def renew(self):
        os.system(f'poff {self.name}')
        time.sleep(0.1)
        os.system(f'pon {self.name}')

    @property
    def interface_id(self):
        return self._id

    @property
    def interface_name(self):
        return self.name


class Socks5(StreamRequestHandler):
    """Socks5 Specification: https://www.rfc-editor.org/rfc/rfc1928"""

    def handle(self):
        if log_stream:
            print(f"New Connection - {self.client_address[0]}:{self.client_address[1]}")

        # METHODS
        header = self.connection.recv(2)
        VER, NMETHODS = struct.unpack("!BB", header)
        if VER != 5:
            raise Exception(f"Not a Socks5 connection!")
        assert NMETHODS > 0
        methods = set(ord(self.connection.recv(1)) for _ in range(NMETHODS))
        if 2 not in methods:
            return self.server.close_request(self.request)
        self.connection.sendall(struct.pack("!BB", 5, 2))

        username = self.authentication()
        if not username:
            return

        # REQUEST
        VER, CMD, RSV, ATYP = struct.unpack("!BBBB", self.connection.recv(4))
        if VER != 5:
            raise Exception(f"Not a Socks5 connection!")
        if ATYP == 1:  # IPV4
            address = socket.inet_ntoa(self.connection.recv(4))
        elif ATYP == 3:  # DOMAINNAME
            address = self.connection.recv(ord(self.connection.recv(1)[0]))
        else:  # IPV6
            address = socket.inet_ntoa(self.connection.recv(4))
        port = struct.unpack('!H', self.connection.recv(2))[0]

        try:
            if CMD == 1:  # CONNECT
                remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.setsockopt(socket.SOL_SOCKET, 25, str(username + '\0').encode('utf-8'))
                remote.connect((address, port))
                bind_address = remote.getsockname()
                if log_stream:
                    print(f"Connected - {address}:{port}")
                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
                port = bind_address[1]
                # VER | REP=Connection refused | RSV | ATYP | BND.ADDR | BND.PORT
                self.connection.sendall(struct.pack("!BBBBIH", 5, 0, 0, ATYP, addr, port))
                self.ongoing_connection(remote)
            else:  # BIND / UDP ASSOCIATE
                return self.server.close_request(self.request)
        except Exception:
            error_lines = format_exc()
            dashl = len(max(error_lines))
            if log_stream:
                print("-"*dashl, "\n", f"Error - {error_lines}", "\n", "-"*dashl)
            # VER | REP=Connection refused | RSV | ATYP | BND.ADDR | BND.PORT
            self.connection.sendall(struct.pack("!BBBBIH", 5, 5, 0, ATYP, 0, 0))
            self.server.close_request(self.request)

    def authentication(self):
        VER = ord(self.connection.recv(1))
        assert VER == 1
        username = self.connection.recv(ord(self.connection.recv(1))).decode('utf-8')
        incoming_password = self.connection.recv(ord(self.connection.recv(1))).decode('utf-8')
        if incoming_password == socks_proxy_password and username in interfaces():
            response = struct.pack("!BB", VER, 0)
            self.connection.sendall(response)
            return username
        response = struct.pack("!BB", VER, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def ongoing_connection(self, remote):
        while True:
            rlist, wlist, xlist = select.select([self.connection, remote], [], [])
            for read in rlist:
                if self.connection == read:
                    data = self.connection.recv(4096)
                    if remote.send(data) <= 0:
                        break
                if remote == read:
                    data = remote.recv(4096)
                    if self.connection.send(data) <= 0:
                        break


def proxy_server():
    class ThreadingTCPServer(ThreadingMixIn, TCPServer):
        pass

    with ThreadingTCPServer(('0.0.0.0', 9011), Socks5) as server:
        server.serve_forever()


def cli():
    global log_stream, socks_proxy_password
    print(f'PPTP-Socks5-Proxy {__version__}\nType "help" for more information.')
    while True:
        input_command = input(">>> ")
        command = input_command.split(" ")[0]
        args = input_command.split(" ")[1:]
        if command == "help":
            print("Usage:\n"
                  "\ttunnels\n"
                  "\tinterfaces\n"
                  "\tnew <vpn server> <interface name> <username> <password>\n"
                  "\ton <interface name>\n"
                  "\toff <interface name>\n"
                  "\trenew <interface name>\n"
                  "\tonall\n"
                  "\toffall\n"
                  "\trenewall\n"
                  "\tlogstream\n"
                  "\tpassword <new password>\n")
        elif command == "tunnels":
            print("PPTP Interfaces (Not Necessarily On): ", ", ".join(tunnels.keys()))
        elif command == "interfaces":
            print("All Interfaces (On): ", ", ".join(interfaces()))
        elif command == "new":
            if len(args) in [1, 2, 4]:
                tunnel = Tunnel(*args)
                tunnels[tunnel.interface_name] = tunnel
                print(f"Interface Set - {tunnel.interface_name}")
            else:
                print("Usage: new <vpn server> <interface name> <username> <password>")
        elif command == "on":
            if len(args) == 1:
                tunnels[args[0]].on()
                print(f"Interface On - {args[0]}")
            else:
                print("Usage: on <interface name>")
        elif command == "off":
            if len(args) == 1:
                tunnels[args[0]].off()
                print(f"Interface Off - {args[0]}")
            else:
                print("Usage: off <interface name>")
        elif command == "offall":
            for tunnel in tunnels.values():
                tunnel.off()
                print(f"Interface Off - {args[0]}")
        elif command == "onall":
            delay = args[0] if len(args) else 0.1
            for tunnel in tunnels.values():
                tunnel.on()
                print(f"Interface On - {tunnel.interface_name}")
                time.sleep(delay)
        elif command == "renew":
            if len(args) == 1:
                tunnels[args[0]].renew()
                print(f"Interface Renewed - {args[0]}")
            else:
                print("Usage: renew <interface name>")
        elif command == "renewall":
            delay = args[0] if len(args) else 0.1
            for tunnel in tunnels.values():
                tunnel.renew()
                print(f"Interface Renewed - {tunnel.interface_name}")
                time.sleep(delay)
        elif command == "logstream":
            print("--- Watching Socks5 Proxy Connections (press enter to quit) ---")
            log_stream = True
            _ = input()
            log_stream = False
            print("-----------------------------------------")
        elif command == "password":
            if len(args) == 1:
                socks_proxy_password = args[0]
                print(f"Password Reset - {args[0]}")
            else:
                print("Usage: password <new password>")


if __name__ == "__main__":
    Thread(target=cli, daemon=True).start()
    proxy_server()
