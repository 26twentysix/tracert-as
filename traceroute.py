import socket
import select
import struct
import ICMPPacket
import whois


class Traceroute:
    MAX_STEPS = 50

    def __init__(self, tries=1, timeout=3):
        self.tries = tries
        self.timeout = timeout

    def get_route(self, host):
        for ttl in range(1, self.MAX_STEPS):
            for tries in range(self.tries):
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', ttl))
                packet = ICMPPacket.ICMPPacket.build_packet()
                sock.sendto(packet, (host, 0))
                s, _, _ = select.select([sock], [], [], self.timeout)
                if s:
                    ans, addr = s[0].recvfrom(1024)
                    header = ans[20:28]
                    request_type, code, checksum, packetID, sequence = struct.unpack("bbHHh", header)
                    whois_info = whois.Whois(addr[0]).get_data()
                    if addr[0].startswith('192.168'):
                        print(f'{ttl}. {addr[0]}\nlocal')
                    else:
                        print(f'{ttl}. {addr[0]}\n{str(whois_info)}')
                    if request_type == 0:
                        return
                else:
                    print(f'{ttl}. *\n')