#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import tqdm
import argparse
from prettytable import PrettyTable
from scapy.all import *
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.contrib.rtps import rtps,pid_types

def get_rtps_pkt(packet):
    return rtps.RTPS(raw(packet[UDP].payload))

def get_rtps_msg_pkt(packet):
    return rtps.RTPSMessage(raw(packet.payload))

def update_guid_topic_mapping(sub_msg, guid_topicName_map):
    cur_topic_name = ""
    cur_endpoint_guid = ""
    for param in sub_msg.data.parameterList.parameterValues:
        if isinstance(param, pid_types.PID_TOPIC_NAME):
            cur_topic_name = param.parameterData[4:].decode('ascii').strip('\x00')
        #   print(f"Found topic name: {cur_topic_name}")
        elif isinstance(param, pid_types.PID_ENDPOINT_GUID):
            cur_endpoint_guid = f"{param.guid.hostId:08x}{param.guid.appId:08x}" \
                            f"{param.guid.instanceId:08x}{param.guid.entityId:08x}"
            # print(f"Found endpoint guid: {cur_endpoint_guid}")
            
    if cur_endpoint_guid and cur_topic_name:
        if cur_endpoint_guid in guid_topicName_map:
            if guid_topicName_map[cur_endpoint_guid] != cur_topic_name:
                print(f"[Warn] endpoint guid {cur_endpoint_guid} has different topic name: "
                        f"{guid_topicName_map[cur_endpoint_guid]} and {cur_topic_name}")
        guid_topicName_map[cur_endpoint_guid] = cur_topic_name

def calculate_bandwidth(timestamps, data_sizes, window_size=1.0):
    if not timestamps or not data_sizes:
        return []
    
    sorted_data = sorted(zip(timestamps, data_sizes), key=lambda x: x[0])
    timestamps, data_sizes = zip(*sorted_data)

    bandwidths = []
    current_window = []
    window_start = timestamps[0]
    for ts, size in zip(timestamps, data_sizes):
        if ts < window_start:
            if ts - window_start > window_size * 2:  # 可根据实际情况调整阈值
                window_start = ts
            continue
        current_window.append((ts, size))
        while ts - window_start > window_size:
            total_size = sum(s for t, s in current_window if t >= window_start)
            bandwidth = total_size / (1024 * window_size)
            bandwidths.append(bandwidth)
            window_start += window_size
            current_window = [(t, s) for t, s in current_window if t >= window_start]
    return bandwidths


def process(pcap_file):
    # data(w)
    w_bytes = 0
    w_count = 0

    # data(p)
    p_bytes = 0
    p_count = 0

    # data(m)
    m_bytes = 0
    m_count = 0

    # data(r)
    r_bytes = 0
    r_count = 0

    # user data submessage size
    data_bytes = 0
    data_count = 0
    # user data payload size
    data_payload_bytes = 0

    # data frag submessage size
    data_frag_bytes = 0
    data_frag_count = 0  

    # info_ts for discovery
    discovery_info_ts_bytes = 0
    discovery_info_ts_count = 0
    # info_ts for userdata
    data_info_ts_count = 0
    data_info_ts_bytes = 0

    # info_dst for discovery
    discovery_info_dst_count = 0
    discovery_info_dst_bytes = 0
    # info_dst for userdata
    data_info_dst_count = 0
    data_info_dst_bytes = 0

    # heartbeat for discovery
    discovery_heartbeat_count = 0
    discovery_heartbeat_bytes = 0
    # heartbeat for userdata
    data_heartbeat_count = 0
    data_heartbeat_bytes = 0

    # acknack for discovery
    discovery_acknack_count = 0
    discovery_acknack_bytes = 0
    # acknack for userdata
    data_acknack_count = 0
    data_acknack_bytes = 0

    # pacaket total
    pkt_total_count = 0
    pkt_bytes_total = 0
    # user data packet count
    pkt_data_count = 0
    pkt_bytes_data = 0
    # discovery data packet count
    pkt_discovery_count = 0
    pkt_bytes_discovery = 0

    # data(w) {endpoint_guid, topic_name}
    guid_topicName_map = {}

    # data {endpoint_guid, {[timestamps], [sizes]}}
    guid_dataInfo_map = {}


    # DATA类型
    # +-------------------+--------------------+-------------------------+
    # | writerEntityIdKey | writerEntityIdKind |       DDS Concept       |
    # +-------------------+--------------------+-------------------------+
    # | 0x100 (256)       | 0xC2 (194)         |        DATA(p)          |
    # | 0x03 (3)          | 0xC2 (194)         |        DATA(w)          |
    # | 0x04 (4)          | 0xC2 (194)         |        DATA(r)          |
    # | 0x200 (512)       | 0xC2 (194)         |        DATA(m)          |
    # +-------------------+--------------------+-------------------------+
    # | any               | 0x03 (3)           |        DATA             |
    # +-------------------+--------------------+-------------------------+
    
    
    scapy.config.conf.max_list_count = 100000
    ip_fragments = {}
    with open(pcap_file, "rb") as f:
        total_packets = sum(1 for _ in RawPcapReader(f))
        f.seek(0)
        reader = tqdm.tqdm(PcapReader(f), total=total_packets, desc="Processing packets")
        packet_no = 0
        for packet in reader:
            packet_no += 1
            # 检查是否为IP分片
            if IP in packet and (packet[IP].flags == 1):
                ip_id = packet[IP].id
                # print(f"[Info] Found IP fragment with ID: {ip_id}, frag: {packet[IP].frag}, flags: {packet[IP].flags}, packet no: {packet_no}")
                if ip_id not in ip_fragments:
                    ip_fragments[ip_id] = []
                ip_fragments[ip_id].append(packet)
                continue
            # 检查是否为最后一个分片
            elif IP in packet and (packet[IP].flags == 0 and packet[IP].frag > 0):
                ip_id = packet[IP].id
                if ip_id in ip_fragments:
                    ip_fragments[ip_id].append(packet)
                    # print(f"[Info] Reassembling IP fragment with ID: {ip_id}, total fragments: {len(ip_fragments[ip_id])}, packet no: {packet_no}")
                    # 重组分片
                    reassembled_payload = b""
                    ip_fragments_sorted = sorted(ip_fragments[ip_id], key=lambda x: x[IP].frag)
                    for frag in ip_fragments_sorted:
                        reassembled_payload += raw(frag[Raw])
                    reassembled_data = raw(ip_fragments_sorted[0])[:42] + reassembled_payload
                    try:
                        # print(f"[Info] Reassembled packet size: {len(reassembled_data)}")
                        packet = Ether(reassembled_data)
                    except Exception as e:
                        print(f"[Error] Failed to reassemble packet: {e}")
                    del ip_fragments[ip_id]

            # 继续处理包
            if UDP not in packet.layers():
                continue
            if not packet[UDP]:
                continue
            rtps_pkt = get_rtps_pkt(packet)
            rtps_timestamp = packet.time
            if rtps_pkt.magic != b'RTPS':
                continue

            is_user_data = True
            is_data_frag = False
            guid_prefix_obj =  rtps_pkt.guidPrefix
            cur_guid_prefix = f"{guid_prefix_obj.hostId:08x}{guid_prefix_obj.appId:08x}{guid_prefix_obj.instanceId:08x}"

            # 多个子消息的情况
            rtps_pkt = get_rtps_msg_pkt(rtps_pkt)
            for sub_msg in rtps_pkt.submessages:
                if isinstance(sub_msg, rtps.RTPSSubMessage_INFO_TS):
                    pass
                elif isinstance(sub_msg, rtps.RTPSSubMessage_INFO_DST):
                    pass
                elif isinstance(sub_msg, rtps.RTPSSubMessage_DATA):
                    if sub_msg.writerEntityIdKind == 0xC2:
                        # built-in data
                        is_user_data = False
                        if sub_msg.writerEntityIdKey == 0x100:
                            p_count += 1
                            p_bytes += len(raw(sub_msg))
                        elif sub_msg.writerEntityIdKey == 0x03:
                            w_count += 1
                            w_bytes += len(raw(sub_msg))
                            # print(f'w_bytes: {len(raw(sub_msg))}')
                            # 解析{endpoint_guid, topic_name}
                            if sub_msg.submessageFlags == 0x05:
                                update_guid_topic_mapping(sub_msg, guid_topicName_map)
                        elif sub_msg.writerEntityIdKey == 0x04:
                            r_count += 1
                            r_bytes += len(raw(sub_msg))
                        elif sub_msg.writerEntityIdKey == 0x200:
                            m_count += 1
                            m_bytes += len(raw(sub_msg))
                    elif sub_msg.writerEntityIdKind == 0x03:
                        # user_data
                        is_user_data = True
                        payload_size = len(raw(sub_msg.data))
                        msg_size = len(raw(sub_msg))
                        data_payload_bytes += payload_size
                        data_bytes += msg_size
                        data_count += 1
                        # get data info
                        cur_endpoint_guid = f"{cur_guid_prefix}{sub_msg.writerEntityIdKey:06x}{sub_msg.writerEntityIdKind:02x}"
                        if cur_endpoint_guid not in guid_dataInfo_map:
                            guid_dataInfo_map[cur_endpoint_guid] = {'timestamps': [], 'sizes': []}
                        guid_dataInfo_map[cur_endpoint_guid]['timestamps'].append(rtps_timestamp)
                        guid_dataInfo_map[cur_endpoint_guid]['sizes'].append(msg_size)
                    else:
                        print(f'unknown data {sub_msg.writerEntityIdKey} {sub_msg.writerEntityIdKind}')
                elif isinstance(sub_msg, rtps.RTPSSubMessage_HEARTBEAT):
                    writerEntityIdKind_t = int.from_bytes(sub_msg.writer_id[-1:], 'big')
                    if writerEntityIdKind_t == 0xC2:
                        is_user_data = False
                        discovery_heartbeat_bytes += len(raw(sub_msg))
                        discovery_heartbeat_count += 1
                    elif writerEntityIdKind_t == 0x03:
                        is_user_data = True
                        data_heartbeat_bytes += len(raw(sub_msg))
                        data_heartbeat_count += 1
                    else:
                        print(f'unknown heartbeat {sub_msg.writer_id} {writerEntityIdKind_t}')
                elif isinstance(sub_msg, rtps.RTPSSubMessage_ACKNACK):
                    writerEntityIdKind_t = int.from_bytes(sub_msg.writer_id[-1:], 'big')
                    if writerEntityIdKind_t == 0xC2:
                        is_user_data = False
                        discovery_acknack_bytes += len(raw(sub_msg))
                        discovery_acknack_count += 1
                    elif writerEntityIdKind_t == 0x03:
                        is_user_data = True
                        data_acknack_bytes += len(raw(sub_msg))
                        data_acknack_count += 1
                    else:
                        print(f'unknown acknack {sub_msg.writer_id}')
                elif isinstance(sub_msg, rtps.RTPSSubMessage_DATA_FRAG):
                    is_user_data = True
                    is_data_frag = True
                    msg_size = int.from_bytes(raw(sub_msg)[2:4], byteorder='little') + 4
                    data_frag_bytes += msg_size
                    data_frag_count += 1
                    # get data_frag info
                    writerEntityId = raw(sub_msg)[12:16].hex()
                    cur_endpoint_guid = f"{cur_guid_prefix}{writerEntityId}"
                    # print(f"[Warn] data_frag {cur_endpoint_guid} {msg_size}")
                    if cur_endpoint_guid not in guid_dataInfo_map:
                        guid_dataInfo_map[cur_endpoint_guid] = {'timestamps': [], 'sizes': []}
                    guid_dataInfo_map[cur_endpoint_guid]['timestamps'].append(rtps_timestamp)
                    guid_dataInfo_map[cur_endpoint_guid]['sizes'].append(msg_size)
                elif isinstance(sub_msg, rtps.RTPSSubMessage_GAP):
                    is_user_data = False
                    pass
                else:
                    print(f'unknown sub_msg : {sub_msg} of type {type(sub_msg)}')
        

            # packet 统计
            #! frag 统计不正确
            if not is_data_frag:
                pkt_total_count += 1
                pkt_bytes_total += len(raw(rtps_pkt))

                if is_user_data:
                    pkt_data_count += 1
                    pkt_bytes_data += len(raw(rtps_pkt)) 
                else:
                    pkt_discovery_count += 1
                    pkt_bytes_discovery += len(raw(rtps_pkt))


    # 统计topic信息
    # {topic_name,{[timestamps], [sizes]}}
    topic_dataInfo_map = {}
    # {topic_name,{total_size, avg_bandwidth, max_bandwidth}}
    topic_bandwidth_map = {}
    for guid, data_info in guid_dataInfo_map.items():
        if guid_topicName_map.get(guid, -1) == -1:
            print(f"[Warn] Not find topic info from edp! data guid {guid} total_size {sum(data_info['sizes']):,}")
        else:
            topic_name = guid_topicName_map[guid]
            # 如果topic_name已存在，合并timestamps和sizes
            if topic_name in topic_dataInfo_map:
                topic_dataInfo_map[topic_name]['timestamps'].extend(data_info['timestamps'])
                topic_dataInfo_map[topic_name]['sizes'].extend(data_info['sizes'])
            else:
                topic_dataInfo_map[topic_name] = data_info

    # 计算带宽
    # 每个topic的带宽
    for topic_name, data_info in topic_dataInfo_map.items():
        if topic_name not in topic_bandwidth_map:
            topic_bandwidth_map[topic_name] = {'total_size': 0, 'avg_bandwidth': 0, 'max_bandwidth': 0}
        topic_bandwidth_map[topic_name]['total_size'] = sum(data_info['sizes']) / 1024
        bandwidths = calculate_bandwidth(data_info['timestamps'], data_info['sizes'])
        if bandwidths:
            # print(f'{topic_name} - {bandwidths}')
            topic_bandwidth_map[topic_name]['avg_bandwidth'] = sum(bandwidths) / len(bandwidths)
            topic_bandwidth_map[topic_name]['max_bandwidth'] = max(bandwidths)

    # 打印结果 
    # summary table
    summary_tab = PrettyTable()
    summary_tab.field_names = [
            '# Pacaket - (bytes)',
            '# Discovery - (bytes)',
            '# UserData - (bytes)',
        ]
    summary_tab.add_row([
        f'{pkt_total_count + data_frag_count:,} - ({pkt_bytes_total + (data_frag_bytes + 24*data_frag_count):,})',
        f'{pkt_discovery_count:,} - ({pkt_bytes_discovery:,})',
        f'{pkt_data_count + data_frag_count:,} - ({pkt_bytes_data + (data_frag_bytes + 24*data_frag_count):,})',
    ])

    # discovery table
    discovery_tab = PrettyTable()
    discovery_tab.field_names = [
            'DATA(w) - (bytes)',
            'DATA(r) - (bytes)',
            'DATA(p) - (bytes)',
            'HEARTBEAT - (bytes)',
            'ACKNACK - (bytes)',
        ]
    discovery_tab.add_row([
            f'{w_count:,} - ({w_bytes:,})',
            f'{r_count:,} - ({r_bytes:,})',
            f'{p_count:,} - ({p_bytes:,})',
            f'{discovery_heartbeat_count:,} - ({discovery_heartbeat_bytes:,})',
            f'{discovery_acknack_count:,} - ({discovery_acknack_bytes:,})',
        ])

    # user data table
    data_tab = PrettyTable()
    data_tab.field_names = [
            'DATA - (bytes)',
            'DATA_FRAG - (bytes)',
            'HEARTBEAT - (bytes)',
            'ACKNACK - (bytes)',
        ]
    data_tab.add_row([
            f'{data_count:,} - ({data_bytes:,})',
            f'{data_frag_count:,} - ({data_frag_bytes:,})',
            f'{data_heartbeat_count:,} - ({data_heartbeat_bytes:,})',
            f'{data_acknack_count:,} - ({data_acknack_bytes:,})',
        ])
    
    # topic size table
    topic_size_tab = PrettyTable()
    topic_size_tab.field_names = [
            'Topic Name',
            'Size - (KB)',
            'AvgBW - (KB/s)',
            'MaxBW - (KB/s)',
        ]
    topic_size_tab.align['Topic Name'] = 'l'
    for topic_name, data_info in sorted(topic_bandwidth_map.items(), key=lambda x: x[1]['total_size'], reverse=True):
        topic_size_tab.add_row([
            topic_name,
            f'{data_info["total_size"]:,.1f}',
            f'{data_info["avg_bandwidth"]:,.1f}',
            f'{data_info["max_bandwidth"]:,.1f}',
        ])

    return (summary_tab, discovery_tab, data_tab, topic_size_tab)


def main():
    parser = argparse.ArgumentParser(description='Parse DDS capture file')
    parser.add_argument('-d','--data', help='Pcap file path', required=True, type=str)

    args = vars(parser.parse_args())
    data = args['data']
    print(f'Processing data in { data }')

    (summary_tab, discovery_tab, data_tab, topic_size_tab) = process(data)

    print("\n", end="")
    print(f"Total Message:\n{summary_tab}")
    print(f"Discovery Submessage:\n{discovery_tab}")
    print(f"UserData Submessage:\n{data_tab}")

    print("\n", end="")
    print(f"Topic Size:\n{topic_size_tab}")

if __name__ == '__main__':
    print(f'Welcome Rtps Analyze Tool v0.1')
    main()