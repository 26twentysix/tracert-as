import struct
import os
import time


class ICMPPacket:
    ICMP_REQUEST_CODE = 8
    ICMP_ECHO_CODE = 0
    SEQUENCE_NUMBER = 1

    @staticmethod
    def d_sum(double):
        s = 0
        for i in range(0, len(double), 2):
            s += (double[i] << 8) + double[i + 1]
        return s

    @staticmethod
    def calculate_checksum(_id, time):
        presum = 0x0800 + _id + 0x001 + ICMPPacket.d_sum(time)
        if presum >> 16 > 0:
            div = presum >> 16
            presum = (presum & 65535) + div
        return (65535 - presum).to_bytes(2, byteorder='big')

    @staticmethod
    def build_packet():
        _id = os.getpid() & 0xffff
        _id = 0x0001
        data = struct.pack('d', time.time())
        checksum = ICMPPacket.calculate_checksum(_id, data)
        return (struct.pack('BB', ICMPPacket.ICMP_REQUEST_CODE, ICMPPacket.ICMP_ECHO_CODE)
                + checksum + struct.pack('>HH', _id, ICMPPacket.SEQUENCE_NUMBER) + data)