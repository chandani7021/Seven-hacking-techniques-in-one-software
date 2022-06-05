import socket
from IPy import IP


class PortScan():
    banners = []
    open_ports = []

    # none ny rakhna
    def __init__(self, target, port_num):
        self.target = target
        self.port_num = port_num

    def scan(self):
        # converted_ip=check_ip(self,target)
        # print('\n' + '[- 0 Scanning Target]' +str(target))
        for port in range(1, self.port_num):
            self.scan_port(port)

    def check_ip(self):
        try:
            IP(self.target)
            return (self.target)
        except ValueError:
            return socket.gethostbyname(self.target)

    # port = 80
    # def get_banner(self):
    #     return s.recv(1024)
    #

    def scan_port(self, port):
        try:
            converted_ip = self.check_ip()
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((converted_ip, port))
            self.open_ports.append(port)
            try:
                # banner=self.get_banner(sock)
                banner = sock.recv(1024).decode().strip('\n').strip('\r')
                self.banners.append(banner)
                # print('[+] Open Port' + str(port) + ' : ' +str(banner.decode().strip('\n')))
            except:
                self.banners.append(' ')
                # print('[+] Open Port' +str(port))
                sock.close()
        except:
            # print('[-] Port' + str(port) + 'Is Closed')
            pass





