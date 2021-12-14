import threading
import socket
import socketserver
from functools import reduce
import binascii

ROOT_DNS = '192.203.230.10'
BLACK_LIST = [
    'dns1.zenon.net'
]


class Scanner:
    __mark_offset_byte = 0
    __mark_offset_bit = 0

    def __init__(self, data: bytes, offset_byte=0, offset_bit=0):
        self.data = data
        self.__offset_byte = offset_byte
        self.__offset_bit = offset_bit

    def next_bits(self, n=1):
        if n > (len(self.data) - self.__offset_byte) * 8 - self.__offset_bit:
            raise RuntimeError(f'Less than {n} bits of data remaining')
        if n > 8 - self.__offset_bit:
            raise RuntimeError('Cannot read the read bit across bytes')
        result = self.data[self.__offset_byte] >> 8 - self.__offset_bit - n & (
                1 << n) - 1
        self.__offset_bit += n
        if self.__offset_bit == 8:
            self.__offset_bit = 0
            self.__offset_byte += 1
        return result

    def next_bytes(self, n=1, convert=True, move=True):
        if not self.__offset_bit == 0:
            raise RuntimeError('The current byte is incomplete')
        if n > len(self.data) - self.__offset_byte:
            raise RuntimeError(f'The remaining data is less than {n} bytes')
        result = self.data[self.__offset_byte: self.__offset_byte + n]
        if move:
            self.__offset_byte += n
        if convert:
            result = int.from_bytes(result, 'big')
        return result

    def next_bytes_until(self, stop, convert=True):
        if not self.__offset_bit == 0:
            raise RuntimeError('The current byte is incomplete')
        end = self.__offset_byte
        while not stop(self.data[end], end - self.__offset_byte):
            end += 1
        result = self.data[self.__offset_byte: end]
        self.__offset_byte = end
        if convert:
            if result:
                result = reduce(lambda x, y: y if (x == '.') else x + y,
                                map(lambda x: chr(x) if (31 < x < 127) else '.', result))
            else:
                result = ''
        return result

    def position(self):
        return self.__offset_byte, self.__offset_bit


class Message:
    def __init__(self, header, question=None, answer=None, authority=None, additional=None):
        self.header = header
        self.question = question
        self.answer = answer
        self.authority = authority
        self.additional = additional

    def to_bytes(self):
        pass

    @classmethod
    def from_bytes(cls, data):
        scanner = Scanner(data)
        header = dict()
        header['ID'] = scanner.next_bytes(2)
        header['QR'] = scanner.next_bits(1)
        header['OPCODE'] = scanner.next_bits(4)
        header['AA'] = scanner.next_bits(1)
        header['TC'] = scanner.next_bits(1)
        header['RD'] = scanner.next_bits(1)
        header['RA'] = scanner.next_bits(1)
        header['Z'] = scanner.next_bits(3)
        header['RCODE'] = scanner.next_bits(4)
        header['QDCOUNT'] = scanner.next_bytes(2)
        header['ANCOUNT'] = scanner.next_bytes(2)
        header['NSCOUNT'] = scanner.next_bytes(2)
        header['ARCOUNT'] = scanner.next_bytes(2)
        print('header:', header)
        questions = list()
        for _ in range(header['QDCOUNT']):
            question = dict()
            question['QNAME'] = scanner.next_bytes_until(
                lambda current, _: current == 0)
            scanner.next_bytes(1)
            question['QTYPE'] = scanner.next_bytes(2)
            question['QCLASS'] = scanner.next_bytes(2)
            questions.append(question)
        print('questions:', questions)
        message = Message(header)
        rrs = list()
        for i in range(header['ANCOUNT'] + header['NSCOUNT'] + header['ARCOUNT']):
            rr = dict()
            rr['NAME'] = cls.handle_compression(scanner)
            if rr['NAME'] == '':
                break
            rr['TYPE'] = scanner.next_bytes(2)
            rr['CLASS'] = scanner.next_bytes(2)
            rr['TTL'] = scanner.next_bytes(4)
            rr['RDLENGTH'] = scanner.next_bytes(2)
            if rr['TYPE'] == 1 or rr['TYPE'] == 28:
                r_data = scanner.next_bytes(rr['RDLENGTH'], False)
                rr['RDATA'] = reduce(
                    lambda x, y: y if (len(x) == 0) else x + '.' + y,
                    map(lambda num: str(num), r_data))
            elif rr['TYPE'] == 2 or rr['TYPE'] == 5:
                rr['RDATA'] = cls.handle_compression(scanner, rr['RDLENGTH'])
            rrs.append(rr)
        answer, authority, additional = list(), list(), list()
        for i, rr in enumerate(rrs):
            if i < header['ANCOUNT']:
                answer.append(rr)
            elif i < header['ANCOUNT'] + header['NSCOUNT']:
                authority.append(rr)
            else:
                additional.append(rr)
        print('answer:', answer)
        print('authority:', authority)
        print('additional:', additional)
        message.header = header
        message.answer = answer
        message.authority = authority
        message.additional = additional
        return message

    @classmethod
    def handle_compression(cls, scanner, length=float("inf")):
        byte = scanner.next_bytes()
        if byte >> 6 == 3:
            pointer = (byte & 0x3F << 8) + scanner.next_bytes()
            return cls.handle_compression(Scanner(scanner.data, pointer))
        data = scanner.next_bytes_until(lambda current, offset: current == 0 or current >> 6 == 3 or offset > length)
        if scanner.next_bytes(move=False) == 0:
            scanner.next_bytes()
            return data
        result = data + '.' + cls.handle_compression(
            Scanner(scanner.data, *scanner.position()))
        scanner.next_bytes(2)
        return result

    def save(self):
        pass


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print('---------------||---------------')
        request_data = self.request[0]
        response_data, address = resolve_domain(request_data, ROOT_DNS)
        client_socket = self.request[1]
        client_socket.sendto(response_data, self.client_address)


def resolve_domain(data, dns_ip):
    print(dns_ip)
    redirect_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    redirect_socket.sendto(data, (dns_ip, 53))
    response_data, address = redirect_socket.recvfrom(1024)
    redirect_socket.close()
    message = Message.from_bytes(response_data)
    if len(message.answer) != 0:
        for mess in message.answer:
            if mess['TYPE'] == 1 and mess['NAME'] not in BLACK_LIST:
                address = mess['RDATA']
                return response_data, address
        return response_data, address[0]
    if len(message.additional) > 0:
        for mess in message.additional:
            if mess['TYPE'] == 1 and mess['NAME'] not in BLACK_LIST:
                return resolve_domain(data, mess['RDATA'])
    elif len(message.authority) > 0:
        for mess in message.authority:
            if 'RDATA' not in mess or mess['NAME'] in BLACK_LIST:
                continue
            server_without_ip = mess['RDATA']
            simple_request_data = string_to_simple_dns_query(server_without_ip)
            print(simple_request_data)
            response_data, new_address = resolve_domain(simple_request_data, ROOT_DNS)
            return resolve_domain(data, new_address)
    return response_data, address[0]


def string_to_simple_dns_query(domain_name):
    parsed = domain_name.split('.')
    result = None
    for item in parsed:
        if len(item) != 0:
            if result is None:
                result = len(item).to_bytes(2, byteorder='big')[1:]
            else:
                result += len(item).to_bytes(2, byteorder='big')[1:]
            result += item.encode("utf-8")
    return binascii.unhexlify("eeee" + "0000" + "0001" + 3 * "0000") + result + binascii.unhexlify("00" + "0001" + "0001")


class Server(socketserver.ThreadingMixIn, socketserver.UDPServer):
    def __init__(self, host, port, handler=Handler):
        super().__init__((host, port), handler)
        self.host = host

    def start(self):
        with self:
            server_thread = threading.Thread(target=self.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            print(f'The DNS server is running at {self.host}...')
            server_thread.join()


if __name__ == "__main__":
    server = Server('127.0.0.1', 53)
    server.start()
