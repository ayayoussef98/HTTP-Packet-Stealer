import struct
import socket
class IpPacket(object):
    """
    Represents the *required* data to be extracted from an IP packet.
    """

    def __init__(self, protocol, ihl, source_address, destination_address, payload):
        self.protocol = protocol
        self.ihl = ihl
        self.source_address = source_address
        self.destination_address = destination_address
        self.payload = payload


class TcpPacket(object):
    """
    Represents the *required* data to be extracted from a TCP packet.
    """

    def __init__(self, src_port, dst_port, data_offset, payload):
        self.src_port = src_port
        self.dst_port = dst_port
        # As far as I know, this field doesn't appear in Wireshark for some reason.
        self.data_offset = data_offset
        self.payload = payload


def parse_raw_ip_addr(raw_ip_addr: bytes) -> str:
    # Converts a byte-array IP address to a string
    # the input is on the form b'\xaa\xab'... a byte array
    alladdress=raw_ip_addr.hex()
    address=""
    for i in range(0,len(alladdress),2):
        initAddress= int(alladdress[i:i+2], 16)
        address =address + str(initAddress) +'.'
    return address[:len(address)-1]


def parse_application_layer_packet(ip_packet_payload: bytes) -> TcpPacket:
    # Parses raw bytes of a TCP packet
    # That's a byte literal (~byte array) check resources section
    unpackedHeader = struct.unpack('!HHLLB',ip_packet_payload[0:13])
    sourcePort = unpackedHeader[0]
    destinationPort = unpackedHeader[1]
    dataOffset = unpackedHeader[4] >> 4
    offset = dataOffset * 4

    payload = struct.unpack('!' + str(ip_packet_payload[offset:].__len__()) + 's', ip_packet_payload[offset:])

    return TcpPacket(sourcePort, destinationPort, dataOffset, payload[0])


def parse_network_layer_packet(ip_packet: bytes) -> IpPacket:
    # Parses raw bytes of an IPv4 packet
    # That's a byte literal (~byte array) check resources section


    unpackedHeader = struct.unpack('! BBHHHBBH', ip_packet[0:12])
    ihl = unpackedHeader[0] & 0x0F
    if (ihl < 5):
        print("Error, expected IHL to be at least 5")
        return IpPacket(-1, -1, -1, -1, b'')

    protocol = unpackedHeader[6]
    sourceAdd = parse_raw_ip_addr(ip_packet[12:16])
    destAdd = parse_raw_ip_addr(ip_packet[16:20])
    offset = ihl * 4
    #payload = struct.unpack('!'+ str(ip_packet[offset:].__len__()) + 's', ip_packet[offset:])
    return IpPacket(protocol, ihl, sourceAdd, destAdd, ip_packet[offset:])

TCP = 0x0006

def setup_socket():
    return socket.socket(socket.AF_INET, socket.SOCK_RAW, TCP)


def main():
    # Un-comment this line if you're getting too much noisy traffic.
    # to bind to an interface on your PC. (or you can simply disconnect from the internet)

    # iface_name = "lo"
    # stealer.setsockopt(socket.SOL_SOCKET,
    #                    socket.SO_BINDTODEVICE, bytes(iface_name, "ASCII"))

    stealer = setup_socket()

    while True:
        packet, address = stealer.recvfrom(4096)
        ip_packet: IpPacket = parse_network_layer_packet(packet)
        if ip_packet.protocol == TCP:
            tcp_packet: TcpPacket = parse_application_layer_packet(ip_packet.payload)
            try:
                tcp_packet.payload.decode("utf-8")
                print("Payload:",tcp_packet.payload)
            except UnicodeError:
                print("None")
        pass
    pass

if __name__ == "__main__":
    main()