from typing import Optional, Callable, List

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet


class TrafficFilter:
    def __init__(self, src: str, dst: str, packet_type=TCP):
        self.src = src
        self.dst = dst
        self.packet_type = packet_type
        self.observed_ips = {self.src, self.dst}

    def filter_protocol(self, pkt: Packet) -> Optional[Packet]:
        return pkt if pkt.haslayer(self.packet_type) else None

    def filter_source(self, pkt: Packet) -> Optional[Packet]:
        return pkt if pkt.haslayer(IP) and pkt[IP].src == self.src else None

    def filter_destination(self, pkt: Packet) -> Optional[Packet]:
        return pkt if pkt.haslayer(IP) and pkt[IP].dst == self.dst else None

    def filter_parties(self, pkt: Packet) -> Optional[Packet]:
        return pkt \
            if pkt.haslayer(IP) and pkt[IP].dst in self.observed_ips and pkt[IP].src in self.observed_ips \
            else None

    def filter(self, pkt: Packet) -> Optional[Packet]:
        return pkt \
            if self.filter_protocol(pkt) and self.filter_parties(pkt) \
            else None

    def filter_collection(self, coll: List[Packet]) -> List[Packet]:
        return [pkt for pkt in coll if self.filter(pkt)]


class CallBackFilter:
    def __init__(self, traffic_filter: TrafficFilter, callback: Callable[[Packet], None]):
        self._traffic_filter = traffic_filter
        self._callback = callback

    def callback(self, pkt: Packet):
        try:
            maybe_packet = self._traffic_filter.filter(pkt)
            if maybe_packet:
                self._callback(maybe_packet)
        except Exception as ex:
            print(f'Exception during packet processing: {ex}')
            print(f'Packet: {pkt.summary()}')
            pkt.show()
