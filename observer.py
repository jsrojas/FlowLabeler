#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import dpkt
import pcap

#Obtain the information inside each packet and save it on a PacketInformation Object
def process_packet(ts, buf, dloff):
    """ process the contents of pcap packet """
    ip_version = 0
    FIN_flag = False
    RST_flag = False
    ACK_flag = False
    if dloff == 14:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if isinstance(eth.data, dpkt.ip.IP):
                ip_version = 4
                ip_pkt_length = ip.len
                if (ip.p == dpkt.ip.IP_PROTO_TCP):
                    tcp = ip.data
                    if(tcp.flags & dpkt.tcp.TH_FIN):
                        FIN_flag = True
                    if(tcp.flags & dpkt.tcp.TH_RST):
                        RST_flag = True
                    if(tcp.flags & dpkt.tcp.TH_ACK):
                        ACK_flag = True

            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip_version = 6
                ip_pkt_length = len(ip.data)
                if (ip.p == dpkt.ip.IP_PROTO_TCP):
                    tcp = ip.data
                    if(tcp.flags & dpkt.tcp.TH_FIN):
                        FIN_flag = True
                    if(tcp.flags & dpkt.tcp.TH_RST):
                        RST_flag = True
                    if (tcp.flags & dpkt.tcp.TH_ACK):
                        ACK_flag = True
            else:
                pass
        except TypeError:
            pass
    else:  # Drop ethernet and move to ip
        try:
            ip = dpkt.ip.IP(buf[dloff:])
            ip_version = 4
        except dpkt.dpkt.UnpackError:
            ip = dpkt.ip6.IP6(buf[dloff:])
            ip_version = 6

    if ip_version == 0:
        return  # we failed to move to ip

    transport = dpkt.udp.UDP(sport=0, dport=0)  # Fake layer for non UPD/TCP packets
    move_up = True
    while move_up:
        if isinstance(ip.data, dpkt.tcp.TCP):
            transport = ip.data
            move_up = False
        elif isinstance(ip.data, dpkt.udp.UDP):
            transport = ip.data
            move_up = False
        elif isinstance(ip.data, dpkt.igmp.IGMP):
            move_up = False
        elif isinstance(ip.data, dpkt.icmp.ICMP):
            move_up = False
        elif isinstance(ip.data, dpkt.icmp6.ICMP6):
            move_up = False
        elif isinstance(ip.data, dpkt.ip6.IP6):
            ip = ip.data
            ip_version = 6
        elif isinstance(ip.data, dpkt.ip.IP):
            ip = ip.data
            ip_version = 4
        elif isinstance(ip.data, dpkt.gre.GRE):
            ip.data = ip.data.data
        elif isinstance(ip.data, dpkt.ppp.PPP):
            ip.data = ip.data.data
        else:
            return

    if ip_version == 4 or ip_version == 6:
        '''
        return PacketInformation(ts=int(ts * 1000), size=ip_pkt_length, content=bytes(ip), ip_version=ip_version,
                                 ip_src=int.from_bytes(ip.src, "big"), ip_dst=int.from_bytes(ip.dst, "big"),
                                 ip_src_b=ip.src, ip_dst_b=ip.dst, src_port=transport.sport,
                                 dst_port=transport.dport, ip_protocol=ip.p, direction=-1, FIN_flag=FIN_flag, RST_flag=RST_flag)
        '''
        return PacketInformation(ts=int(ts * 1000), size=ip_pkt_length, content=bytes(ip), ip_version=ip_version,
                                 ip_src=int.from_bytes(ip.src, "big"), ip_dst=int.from_bytes(ip.dst, "big"),
                                 ip_src_b=ip.src, ip_dst_b=ip.dst, src_port=transport.sport,
                                 dst_port=transport.dport, ip_protocol=ip.p, direction=-1, FIN_flag=FIN_flag,
                                 RST_flag=RST_flag, ts_float=ts, ACK_flag = ACK_flag)
    else:
        return
#####################################--PACKET INFORMATION CLASS--########################################################################################
#This class creates the object that will store the information extracted from each packet
class PacketInformation:
    """ Abstraction structure for any packet input type."""
    def __init__(self, ts, size, content, ip_version, ip_src, ip_dst,
                 ip_protocol, ip_src_b, ip_dst_b, src_port, dst_port, direction, FIN_flag, RST_flag, ts_float, ACK_flag):
        self.ts = ts
        self.ts_float = ts_float
        self.size = size
        self.content = content
        self.ip_version = ip_version
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.ip_protocol = ip_protocol
        self.ip_src_b = ip_src_b
        self.ip_dst_b = ip_dst_b
        self.src_port = src_port
        self.dst_port = dst_port
        self.direction = direction
        self.FIN_flag = FIN_flag
        self.RST_flag = RST_flag
        self.ACK_flag = ACK_flag
##################################################################################################################################################


######################################################--OBSERVER CLASS--##############################################################################
#Creates an Observer Object that expects for a pcap file or a network interface to get and process each packet through an iterable generator
class Observer:
    def __init__(self, source=None,
                 snaplen=65535,
                 promisc=False,
                 timeout_ms=0,
                 no_buffering=1,
                 rfmon=0,
                 timestamp_in_ns=0):
        self.source = source
        self.snaplen = snaplen
        self.promisc = promisc
        self.timeout_ms = timeout_ms
        self.no_buffering = no_buffering
        self.timestamp_in_ns = timestamp_in_ns
        self.rfmon = rfmon
        self.packet_generator = None
        try:
            self.packet_generator = pcap.pcap(name=self.source,
                                              snaplen=self.snaplen,
                                              promisc=self.promisc,
                                              timeout_ms=self.timeout_ms,
                                              immediate=self.no_buffering,
                                              timestamp_in_ns=self.timestamp_in_ns,
                                              rfmon=self.rfmon)
        except OSError:
            print("ERROR: Streamer initialized on unfound device (root privilege needed for live capture \
or pcap file path unfound).")

    def __iter__(self):
        if self.packet_generator is not None:
            while True:
                try:
                    timestamp, packet = next(self.packet_generator)
                    packet_information = process_packet(timestamp, packet, self.packet_generator.dloff)
                    yield packet_information
                except StopIteration:
                    break
                except KeyboardInterrupt:
                    raise StopIteration
#########################################################################################################################################################