import socket
import json
from collections import deque
import select
import sys


class QmpChannel(object):
    """docstring for QemuChannel"""
    def __init__(self, portnum):
        # Create a TCP/IP socket
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        server_address = ('localhost', portnum)
        print('connecting to {} port {}'.format(*server_address))
        self.s.settimeout(10)
        print("timeout = ", self.s.gettimeout())
        self.s.connect(server_address)
        self.event_queue = deque()

        
    def get_msg(self):
        msg = b''
        b = b'\x00'
        while b != b'\n':
            b = self.s.recv(1)
            msg += b
        return msg.decode()

    def maybe_get_msg(self):
        read_sockets, _, error_sockets = select.select([self.s], [], [], 1)
        if read_sockets:
            if read_sockets[0] == self.s:
                return self.get_msg()
        else:
            return None

    def get_response(self):
        while True:
            msg = self.get_msg()
            parsed_msg = json.loads(msg)
            if 'return' in parsed_msg:
                return parsed_msg
            else:
                self.event_queue.append(parsed_msg)

    def connect(self):
        self.s.recv(1024)
        self.s.send("{ 'execute': 'qmp_capabilities' }".encode())
        self.s.recv(1024)

    def send_cmd(self, cmd):
        ''' convert dict to bytes and send it, return response '''
        msg = str(cmd).encode()
        self.s.send(msg)
        return self.get_response()

    def pop_event(self):
        return self.event_queue.popleft()
