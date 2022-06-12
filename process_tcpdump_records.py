import dpkt
import ipaddress
import subprocess
import MySQLdb
import glob
import os
import datetime
from time import sleep
import re
import config
import pickle


class TcpdumpTools():
    def get_domain_by_dig(self, ip_addr_str: str) -> str:
        stdout: str = str(subprocess.run(
            ['dig', '-x', ip_addr_str, '+short'], capture_output=True).stdout)
        domain: str = re.sub(r"^b|\\n|'|\"", '', stdout)
        print(f'Got domain {domain} from {ip_addr_str} by dig')
        if len(domain) == 0:
            return ip_addr_str
        else:
            return domain

    def is_private(self, ip_addr_obj: ipaddress.IPv6Address | ipaddress.IPv4Address) -> bool:
        if isinstance(ip_addr_obj, ipaddress.IPv4Address):  # IPv4
            return ip_addr_obj.is_private
        else:
            return format(ip_addr_obj).startswith(config.IPV6_PREFIX)  # IPv6

    def convert_domain_to_nickname(self, domain: str) -> str:
        if domain is None:
            return None
        nickname_dic: dict[str, str] = {
            'dropbox': 'Dropbox',
            'aws': 'AWS',
            'amazon': 'Amazon',
            'slack': 'Slack',
            'line': 'LINE',
            'google': 'Google',
            'microsoft': 'Microsoft',
            'apple': 'Apple',
            'twitter': 'Twitter',
            'ms-python': 'MS-Python',
            'msn': 'MSN'}
        for key in nickname_dic:
            if key in domain:
                return nickname_dic[key]
        splitted: list[str] = domain.split('.')
        idx: int = len(splitted) - 1
        for idx in reversed(range(len(splitted))):
            if len(splitted[idx]) > 3:
                return splitted[idx].capitalize()
        else:
            return domain.capitalize()

    # def is_file_in_use(self, file: str) -> bool:
    #     try:
    #         os.rename(file, file + '_')
    #         os.rename(file + '_', file)
    #     except PermissionError:
    #         return True
    #     else:
    #         return False


class SQLTools(TcpdumpTools):
    def __init__(self) -> None:
        super().__init__()
        # Connect to database
        self.connection = MySQLdb.connect(
            host='localhost',
            user=config.USERNAME,
            passwd=config.PASSWORD,
            db='network')
        self.cursor = self.connection.cursor()

    def search_ip_addr_from_dns_records(self, ip_addr_str: str) -> tuple[int, str, bool]:
        # Search table 'dns_records' and get the corresponding domain name
        self.cursor.execute(
            f"SELECT id, domain, is_definite FROM dns_records WHERE ip_addr='{ip_addr_str}'")
        rows: tuple(tuple[int, str, bool]) = self.cursor.fetchall()
        if len(rows) > 0:
            return rows[0]  # (id, domain, is_definite)
        else:
            return None

    def register_ip_addr_to_dns_records(
            self,
            ip_addr_str: str,
            domain: str,
            is_definite: bool) -> None:
        queries = []
        ans_from_db: tuple[int, str, bool] = self.search_ip_addr_from_dns_records(ip_addr_str)
        if ans_from_db is not None:  # If the address already exists in the database
            if ans_from_db[2]:  # If already definite, skip
                return
            if is_definite:
                # Update the entry in the dns_records
                queries.append(
                    f"UPDATE dns_records SET is_definite=1, domain='{domain}' WHERE id={ans_from_db[0]};")
                # Update the corresponding entries in the tcpdump_records
                nickname: str = self.convert_domain_to_nickname(domain)
                queries.append(
                    f"UPDATE tcpdump_records SET domain='{domain}', nickname='{nickname}' WHERE domain='{ans_from_db[1]}';")
        else:
            # Insert the IP address and domain name to the table 'dns_records'
            queries.append(
                f"INSERT INTO dns_records VALUES (DEFAULT, DEFAULT, '{ip_addr_str}', '{domain}', {int(is_definite)})")
        for query in queries:
            print(query)
            self.cursor.execute(query)
            self.connection.commit()

    def register_dic_to_tcpdump_records(self, ts_float: float, dic: dict[str, int]) -> None:
        print(dic)
        ts_str: str = datetime.datetime.fromtimestamp(ts_float).strftime('%Y-%m-%d %H:%M:%S')
        for key in dic:  # dic = {domain: count}
            # Skip entry whose count is less than 5
            nickname: str = self.convert_domain_to_nickname(key)
            query: str = f"INSERT INTO tcpdump_records VALUES (DEFAULT, '{ts_str}', '{key}', '{nickname}', {dic[key]})"
            print(query)
            self.cursor.execute(query)
        self.connection.commit()

    def convert_ip_addr_to_domain(self, ip_addr_str: str) -> str:
        # Search IP address to from database
        res_from_db: tuple[int, str, bool] = self.search_ip_addr_from_dns_records(ip_addr_str)
        if res_from_db is not None:  # Already in the database
            return res_from_db[1]
        # If the given IP address was not found in the database, get using dig command
        res_from_dig: str = self.get_domain_by_dig(ip_addr_str)
        # Register the pair of the IP address and domain to database with definite flag False
        if res_from_dig is not None:
            self.register_ip_addr_to_dns_records(ip_addr_str, res_from_dig, False)
        return res_from_dig


class TcpdumpRecorder(SQLTools):
    def __init__(self) -> None:
        super().__init__()
        self.dic: dict[str, int] = {}

    def add_to_dic(self, domain: str) -> None:
        if domain is None:
            return
        if domain in self.dic.keys():
            self.dic[domain] += 1
        else:
            self.dic[domain] = 1

    def is_dns_data(self, data) -> bool:
        try:
            dpkt.dns.DNS(data.data)
            return True
        except BaseException:
            return False

    def process_dns(self, data) -> None:
        dns = dpkt.dns.DNS(data.data)
        print(data.data)
        if len(dns.qd) == 0:
            return
        domain: str = dns.qd[0].name
        for ans in dns.an:
            if hasattr(ans, 'ip'):
                ip_addr_str = format(ipaddress.ip_address(ans.ip))
            elif hasattr(ans, 'ip6'):
                ip_addr_str = format(ipaddress.ip_address(ans.ip6))
            else:
                continue
            print(f'processing DNS with {domain} and {ip_addr_str}...')
            self.register_ip_addr_to_dns_records(ip_addr_str, domain, True)

    def process_file(self, file: str) -> None:
        self.dic: dict[str, int] = {}
        try:
            pcr = dpkt.pcap.Reader(open(file, 'rb'))
            for ts, buf in pcr:
                eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.dpkt.NeedData:
            print(f'raised NeedData Error')
            return
        ts_float: float = 0
        pcr = dpkt.pcap.Reader(open(file, 'rb'))
        for ts, buf in pcr:
            eth = dpkt.ethernet.Ethernet(buf)
            ip: dpkt.ip.IP = eth.data
            if not hasattr(ip, 'data'):
                continue
            data = ip.data  # <dpkt.tcp.TCP>, <dpkt.udp.UDP>, ...
            print(type(data))
            # Process DNS
            if self.is_dns_data(data):
                self.process_dns(data)
                continue
            # Process others
            for ip_addr_b in [eth.data.dst, eth.data.src]:
                # print(ip_addr_b)
                try:
                    ip_addr_obj = ipaddress.ip_address(ip_addr_b)
                except ValueError:
                    print(f'{ip_addr_b} is not valid IP address')
                    continue
                if self.is_private(ip_addr_obj):
                    continue
                ip_addr_str: str = format(ip_addr_obj)
                print(ip_addr_str)
                domain: str = self.convert_ip_addr_to_domain(ip_addr_str)
                self.add_to_dic(domain)
            ts_float = ts
        self.register_dic_to_tcpdump_records(ts_float, self.dic)
        os.remove(file)

    def iterate_files(self) -> None:
        # files = glob.glob('./tokuran*.pcap')
        files: list[str] = glob.glob('./*.pcap')
        for file in files:
            print(file)
            print('filesize:', os.path.getsize(file))
            # if self.is_file_in_use(file):
            #     continue
            # self.process_file(file)
            try:
                self.process_file(file)
            except BaseException:
                continue


if __name__ == '__main__':
    tcpdump_recorder = TcpdumpRecorder()
    while (1):
        tcpdump_recorder.iterate_files()
        sleep(10)
