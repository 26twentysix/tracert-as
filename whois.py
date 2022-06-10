import re
import socket


class HostData:
    def __init__(self, server=None, country=None, as_number=None, netname=None, is_info=False):
        self.server = server
        self.country = country
        self.as_number = as_number
        self.netname = netname
        self.is_info = is_info

    def __bool__(self):
        return self.is_info

    def __str__(self):
        if self.is_info:
            ret_str = f''
            if self.netname:
                ret_str += f':{self.netname}:'
            if self.as_number:
                ret_str += f':{self.as_number}:'
            if self.country:
                ret_str += f':{self.country}:'
            return ret_str[1:-1].replace('::', ', ')
        else:
            return ''


class Whois:
    def __init__(self, host):
        self.host = host
        self.whois_servers = {}
        self.whois_servers["whois.ripe.net"] = self.get_data_RIPE
        self.whois_servers["whois.arin.net"] = self.get_data_ARIN
        self.whois_servers["whois.apnic.net"] = self.get_data_APNIC
        self.whois_servers["whois.afrinic.net"] = self.get_data_AfriNIC
        self.whois_servers["whois.lacnic.net"] = self.get_data_LACNIC

    def get_data(self):
        for server in self.whois_servers:
            parsed_data = self.whois_servers[server]()
            if parsed_data:
                return parsed_data

    def get_info_from_response(self, response):
        if response:
            response = response[0]
            info = response.split(":")[1]
            info =  info.replace(" ", "")
            info = info.replace("\n", "")
            return info
        return None

    def get_data_RIPE(self):
        server = "whois.ripe.net"
        response = self.connect(server)
        country = self.get_info_from_response(re.findall(r"country:\s*\w{2}", response))
        as_number = self.get_info_from_response(re.findall(r"origin:\s*AS\d*\s", response))
        netname = self.get_info_from_response(re.findall(r"netname:\s*[-\w]*\s", response))
        if netname is None or country == "EU":
            return HostData()
        return HostData(is_info=True, server=server, country=country, as_number=as_number, netname=netname)

    def get_data_APNIC(self):
        server = "whois.apnic.net"
        response = self.connect(server)
        country = self.get_info_from_response(re.findall(r"country:\s*\w{2}", response))
        as_number = self.get_info_from_response(re.findall(r"origin:\s*AS\d*\s", response))
        netname = self.get_info_from_response(re.findall(r"netname:\s*[-\w]*\s", response))
        if country is None:
            return HostData()
        return HostData(is_info=True, server=server, country=country, as_number=as_number, netname=netname)

    def get_data_AfriNIC(self):
        server = "whois.afrinic.net"
        response = self.connect(server)
        country = self.get_info_from_response(re.findall(r"country:\s*\w{2}", response))
        as_number = self.get_info_from_response(re.findall(r"origin:\s*AS\d*\s", response))
        netname = self.get_info_from_response(re.findall(r"netname:\s*[-\w]*\s", response))
        if country is None:
            return HostData()
        return HostData(is_info=True, server=server, country=country, as_number=as_number, netname=netname)


    def get_data_ARIN(self):
        server = "whois.arin.net"
        response = self.connect(server)
        country = self.get_info_from_response(re.findall(r"Country:\s*\w{2}", response))
        as_number = self.get_info_from_response(re.findall(r"PostalCode:\s*\d*\s", response))
        netname = self.get_info_from_response(re.findall(r"NetName:\s*[-\w]*\s", response))
        if country is None:
            return HostData()
        return HostData(is_info=True, server=server, country=country, as_number=as_number, netname=netname)

    def get_data_LACNIC(self):
        server = "whois.lacnic.net"
        response = self.connect(server)
        country = self.get_info_from_response(re.findall(r"country:\s*\w{2}", response))
        as_number = self.get_info_from_response(re.findall(r"aut-num:\s*AS\d*\s", response))
        if country is None:
            return HostData()
        return HostData(is_info=True, server=server, country=country, as_number=as_number)

    def connect(self, server):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((server, 43))
        except Exception:
            print(f'cant connect to "{server}"')
        sock.sendall((str(self.host) + "\r\n").encode())
        data = b''
        while True:
            temp = sock.recv(1024)
            if not temp:
                break
            data += temp
        sock.close()
        try:
            return data.decode()
        except UnicodeDecodeError:
            return data.decode("latin-1")