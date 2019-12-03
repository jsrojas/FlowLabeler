from streamer import Streamer
import pandas as pd
import time
import sys
"""
This application obtains all the bidirectional flow statistics and application layer protocols from IP packets. 

It can be executed in live-capture mode or in file-reader mode (reading pcap files).

Since the live capture mode needs the name of the network interface the following command can be useful:
- LIST NETWORK INTERFACES COMMAND:
    - FOR LINUX: ip link show

MODES OF OPERATION EXAMPLES:
- LIVE CAPTURE MODE (needs to be executed with sudo):
    The structure of the command is the following:
        sudo python3 main-file.py [operation mode] [network-interface] [CSV FILE NAME]
    Examples:
        sudo python3 main-file.py i wlp0s20f3 /home/jsrojas/Juan/Unicauca/Doctorado/Test.csv
        sudo python3 main-file.py i enp6s0f1 /home/jsrojas/Juan/Unicauca/Doctorado/PhD\ Internship/Test.csv
- FILE READER MODE:
    The structure of the command is the following:
        python3 main-file.py [operation mode] [path-to-pcap-file] [CSV FILE NAME]
    Examples:
        python3 main-file.py f file.pcap Test.csv
        python3 main-file.py f /home/jsrojas/Juan/Unicauca/Doctorado/PhD\ Internship/Task\ 1\ -\ Comparison\ of\ Flow\ Monitoring\ tools/Facebook-packets.pcap /home/jsrojas/Juan/Unicauca/Doctorado/PhD\ Internship/Test.csv
"""

# Obtain the parameters from the CLI command (operation mode, source, csv file route)
operation_mode = sys.argv[1]
input_file = sys.argv[2]
output_file = sys.argv[3]

# If the operation mode is live capture
if(operation_mode == "i"):
    try:
        print('STARTING LIVE CAPTURE MODE')
        processing_start_time = time.time()
        capture_streamer = Streamer(source=input_file, capacity=128000, active_timeout=120, inactive_timeout=15)
        # DATAFRAME CREATION
        df_flows = pd.DataFrame(columns=['flow_key',
                                         'src_ip',
                                         'src_port',
                                         'dst_ip',
                                         'dst_port',
                                         'proto',
                                         'pktTotalCount',
                                         'octetTotalCount',
                                         'min_ps',
                                         'max_ps',
                                         'avg_ps',
                                         'std_dev_ps',
                                         'flowStart',
                                         'flowEnd',
                                         'flowDuration',
                                         'min_piat',
                                         'max_piat',
                                         'avg_piat',
                                         'std_dev_piat',
                                         'f_pktTotalCount',
                                         'f_octetTotalCount',
                                         'f_min_ps',
                                         'f_max_ps',
                                         'f_avg_ps',
                                         'f_std_dev_ps',
                                         'f_flowStart',
                                         'f_flowEnd',
                                         'f_flowDuration',
                                         'f_min_piat',
                                         'f_max_piat',
                                         'f_avg_piat',
                                         'f_std_dev_piat',
                                         'b_pktTotalCount',
                                         'b_octetTotalCount',
                                         'b_min_ps',
                                         'b_max_ps',
                                         'b_avg_ps',
                                         'b_std_dev_ps',
                                         'b_flowStart',
                                         'b_flowEnd',
                                         'b_flowDuration',
                                         'b_min_piat',
                                         'b_max_piat',
                                         'b_avg_piat',
                                         'b_std_dev_piat',
                                         'flowEndReason',
                                         'category',
                                         'application_name'])

        print('\nSaving flow statistics in dataframe')

        # APPENDING FLOW RECORDS TO THE DATAFRAME
        flows_counter = 0

        for idx, flow in enumerate(capture_streamer):
            flows_counter += 1
            df_flows = df_flows.append({'flow_key': flow.key,
                                        'src_ip': flow.ip_src,
                                        'src_port': flow.src_port,
                                        'dst_ip': flow.ip_dst,
                                        'dst_port': flow.dst_port,
                                        'proto': flow.ip_protocol,
                                        'pktTotalCount': flow.pktTotalCount,
                                        'octetTotalCount': flow.octetTotalCount,
                                        'min_ps': flow.min_pkt_size,
                                        'max_ps': flow.max_pkt_size,
                                        'avg_ps': flow.avg_pkt_size,
                                        'std_dev_ps': flow.std_dev_pkt_size,
                                        'flowStart': flow.start_time,
                                        'flowEnd': flow.end_time,
                                        'min_piat': flow.min_piat,
                                        'max_piat': flow.max_piat,
                                        'avg_piat': flow.avg_piat,
                                        'std_dev_piat': flow.std_dev_piat,
                                        'f_pktTotalCount': flow.src_to_dst_pkts,
                                        'f_octetTotalCount': flow.src_to_dst_bytes,
                                        'f_min_ps': flow.f_min_pkt_size,
                                        'f_max_ps': flow.f_max_pkt_size,
                                        'f_avg_ps': flow.f_avg_pkt_size,
                                        'f_std_dev_ps': flow.f_std_dev_pkt_size,
                                        'f_flowStart': flow.f_start_time,
                                        'f_flowEnd': flow.f_end_time,
                                        'f_flowDuration': flow.f_flowDuration,
                                        'f_min_piat': flow.f_min_piat,
                                        'f_max_piat': flow.f_max_piat,
                                        'f_avg_piat': flow.f_avg_piat,
                                        'f_std_dev_piat': flow.f_std_dev_piat,
                                        'b_pktTotalCount': flow.dst_to_src_pkts,
                                        'b_octetTotalCount': flow.dst_to_src_bytes,
                                        'b_min_ps': flow.b_min_pkt_size,
                                        'b_max_ps': flow.b_max_pkt_size,
                                        'b_avg_ps': flow.b_avg_pkt_size,
                                        'b_std_dev_ps': flow.b_std_dev_pkt_size,
                                        'b_flowStart': flow.b_start_time,
                                        'b_flowEnd': flow.b_end_time,
                                        'b_flowDuration': flow.b_flowDuration,
                                        'b_min_piat': flow.b_min_piat,
                                        'b_max_piat': flow.b_max_piat,
                                        'b_avg_piat': flow.b_avg_piat,
                                        'b_std_dev_piat': flow.b_std_dev_piat,
                                        'flowEndReason': flow.export_reason,
                                        'category': flow.classifiers['ndpi']['category_name'],
                                        'application_name': flow.classifiers['ndpi']['application_name']},
                                       ignore_index=True)

            if (idx + 1) % 10 == 0:
                print('\nCurrent generated flows: ', flows_counter)
        # Creating the flowDuration column
        df_flows['flowDuration'] = df_flows['flowEnd'] - df_flows['flowStart']
        # Creating CSV file
        print("\n************************ALL PACKETS HAVE BEEN PROCESSED****************************************")
        print('\nCREATING CSV FILE........')
        df_flows.to_csv(output_file, index=None, header=True)
        print('\n*****CSV FILE CREATED******')
        print("\nNUMBER OF ANALYZED PACKETS:", capture_streamer.processed_packets)
        print("\nNUMBER OF FLOWS:", capture_streamer.flows_number)
        processing_end_time = time.time()
        print('\nPROCESSING TIME:', processing_end_time - processing_start_time, 'seconds')
        print("\n¡¡¡¡PROCESS FINISHED SUCCESSFULY!!!!")


    except (KeyboardInterrupt, SystemExit):
        print("LIVE CAPTURE INTERRUPTED")

# If the operation mode is file mode
elif(operation_mode == "f"):
    processing_start_time = time.time()
    capture_streamer = Streamer(source=input_file, capacity=128000,active_timeout=120, inactive_timeout=15)
    #DATAFRAME CREATION
    df_flows = pd.DataFrame(columns=['flow_key',
                                 'src_ip',
                                 'src_port',
                                 'dst_ip',
                                 'dst_port',
                                 'proto',
                                 'pktTotalCount',
                                 'octetTotalCount',
                                 'min_ps',
                                 'max_ps',
                                 'avg_ps',
                                 'std_dev_ps',
                                 'flowStart',
                                 'flowEnd',
                                 'flowDuration',
                                 'min_piat',
                                 'max_piat',
                                 'avg_piat',
                                 'std_dev_piat',
                                 'f_pktTotalCount',
                                 'f_octetTotalCount',
                                 'f_min_ps',
                                 'f_max_ps',
                                 'f_avg_ps',
                                 'f_std_dev_ps',
                                 'f_flowStart',
                                 'f_flowEnd',
                                 'f_flowDuration',
                                 'f_min_piat',
                                 'f_max_piat',
                                 'f_avg_piat',
                                 'f_std_dev_piat',
                                 'b_pktTotalCount',
                                 'b_octetTotalCount',
                                 'b_min_ps',
                                 'b_max_ps',
                                 'b_avg_ps',
                                 'b_std_dev_ps',
                                 'b_flowStart',
                                 'b_flowEnd',
                                 'b_flowDuration',
                                 'b_min_piat',
                                 'b_max_piat',
                                 'b_avg_piat',
                                 'b_std_dev_piat',
                                 'flowEndReason',
                                 'category',
                                 'application_name'])
    print('\nSaving flow statistics in dataframe')
    # APPENDING FLOW RECORDS TO THE DATAFRAME
    flows_counter = 0
    for idx, flow in enumerate(capture_streamer):
        flows_counter += 1
        df_flows = df_flows.append({'flow_key': flow.key,
                                'src_ip': flow.ip_src,
                                'src_port': flow.src_port,
                                'dst_ip': flow.ip_dst,
                                'dst_port': flow.dst_port,
                                'proto': flow.ip_protocol,
                                'pktTotalCount': flow.pktTotalCount,
                                'octetTotalCount': flow.octetTotalCount,
                                'min_ps': flow.min_pkt_size,
                                'max_ps': flow.max_pkt_size,
                                'avg_ps': flow.avg_pkt_size,
                                'std_dev_ps': flow.std_dev_pkt_size,
                                'flowStart': flow.start_time,
                                'flowEnd': flow.end_time,
                                'min_piat':flow.min_piat,
                                'max_piat': flow.max_piat,
                                'avg_piat': flow.avg_piat,
                                'std_dev_piat': flow.std_dev_piat,
                                'f_pktTotalCount': flow.src_to_dst_pkts,
                                'f_octetTotalCount': flow.src_to_dst_bytes,
                                'f_min_ps': flow.f_min_pkt_size,
                                'f_max_ps': flow.f_max_pkt_size,
                                'f_avg_ps': flow.f_avg_pkt_size,
                                'f_std_dev_ps': flow.f_std_dev_pkt_size,
                                'f_flowStart': flow.f_start_time,
                                'f_flowEnd': flow.f_end_time,
                                'f_flowDuration': flow.f_flowDuration,
                                'f_min_piat': flow.f_min_piat,
                                'f_max_piat': flow.f_max_piat,
                                'f_avg_piat': flow.f_avg_piat,
                                'f_std_dev_piat': flow.f_std_dev_piat,
                                'b_pktTotalCount': flow.dst_to_src_pkts,
                                'b_octetTotalCount': flow.dst_to_src_bytes,
                                'b_min_ps': flow.b_min_pkt_size,
                                'b_max_ps': flow.b_max_pkt_size,
                                'b_avg_ps': flow.b_avg_pkt_size,
                                'b_std_dev_ps': flow.b_std_dev_pkt_size,
                                'b_flowStart': flow.b_start_time,
                                'b_flowEnd': flow.b_end_time,
                                'b_flowDuration': flow.b_flowDuration,
                                'b_min_piat': flow.b_min_piat,
                                'b_max_piat': flow.b_max_piat,
                                'b_avg_piat': flow.b_avg_piat,
                                'b_std_dev_piat': flow.b_std_dev_piat,
                                'flowEndReason': flow.export_reason,
                                'category': flow.classifiers['ndpi']['category_name'],
                                'application_name': flow.classifiers['ndpi']['application_name']},
                               ignore_index=True)
        if (idx + 1) % 10 == 0:
            print('\nCurrent generated flows: ', flows_counter)

    #Creating the flowDuration column
    df_flows['flowDuration'] = df_flows['flowEnd'] - df_flows['flowStart']

    #Creating CSV file
    print("\n************************ALL PACKETS HAVE BEEN PROCESSED****************************************")
    print('\nCREATING CSV FILE........')
    df_flows.to_csv(output_file, index=None, header=True)
    print('\n*****CSV FILE CREATED******')
    print("\nNUMBER OF ANALYZED PACKETS:", capture_streamer.processed_packets)
    print("\nNUMBER OF FLOWS:", capture_streamer.flows_number)
    processing_end_time = time.time()
    print('\nPROCESSING TIME:', processing_end_time-processing_start_time, 'seconds')
    print("\n¡¡¡¡PROCESS FINISHED SUCCESSFULY!!!!")

# In case a wrong operation mode was required by the user
else:
    print("Wrong operation mode, please choose i for live capture mode or f for file mode")