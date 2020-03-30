# FlowLabeler

FlowLabeler is an application capable of processing IP packets either from pcap files or on a live capture mode to generate a csv file storing flow records containing bidirectional statistics and the application layer protocol (Youtube, Facebook, etc) using nDPI library.

It is important to mention that this application is based on nfstream release 0.5.0 available on the following link:
                            
			    https://github.com/aouinizied/nfstream/tree/v0.5.0/nfstream
  
And also on FlowRecorder available on the following link:
                                      
				      https://github.com/drnpkr/flowRecorder

This application was created using **python 3.6.8**

# REQUIRED PYTHON MODULES

Modules that need to be installed (with pip for example):

-pandas

-dpkt

-numpy

-lru-dict

-pypcap - it is necessary to have libpcap installed in the OS before installing pypcap. To install libpcap in Linux use:

		                      	 sudo apt-get install libpcap-dev

The application can be executed by command line in live-capture mode or in file-reader mode (reading pcap files).


# LIST NETWORK INTERFACES COMMAND

Since the live capture mode needs the name of the network interface the following command can be useful:

    
   **- FOR LINUX:**
    						
						ip link show

# MODES OF OPERATION

The application must be execute through the main-file.py in the command line

**- LIVE CAPTURE MODE (needs to be executed with sudo):**
    
  The structure of the command is the following:
        
		sudo python3 main-file.py [operation mode (i or f)] [network-interface] [CSV FILE NAME]
  Examples:
        
			sudo python3 main-file.py i wlp0s20f3 /home/jsrojas/Test.csv
        		
			sudo python3 main-file.py i enp6s0f1 /home/jsrojas/Test.csv
        
**- FILE READER MODE:**
    
  The structure of the command is the following:
        
			python3 main-file.py [operation mode] [path-to-pcap-file] [CSV FILE NAME]
  Examples:
        
					python3 main-file.py f file.pcap Test.csv
        
			python3 main-file.py f /home/jsrojas/Facebook-packets.pcap /home/jsrojas/Test.csv
			
# Attributes List - 49 attributes
-***flow_key*** - Flow identifier through a hash algorithm

-***src_ip_numeric*** - Source IP in decimal format

-***src_ip*** - Source IP in network format
 
 -***src_port*** - Source port number
 
 -***dst_ip*** - Destination IP in network format
 
 -***dst_port*** - Destination port number
 
 -***proto*** - Transport protocol number according to IANA (e.g., 1 for ICMP, 6 for TCP, 17 for UDP)
 
 -***pktTotalCount*** - Total number of packets in both directions
 
 -***octetTotalCount*** - Total of bytes exchanged in both directions focusing on the IP payload only
  
  -***min_ps*** - Minimum packet size in both directions
   
  -***max_ps*** - Maximum packet size in both directions
   
  -***avg_ps*** - Average packet size in both directions 
   
  -***std_dev_ps*** - Packet size standard deviation in both directions 
   
  -***flowStart*** - Flow start time in seconds using unix time format
   
  -***flowEnd*** - Flow end time in seconds using unix time format
   
  -***flowDuration*** - Total flow duration in seconds using unix time format
   
  -***min_piat*** - Minimum packet interarrival time in both directions
   
  -***max_piat*** - Maximum packet interarrival time in both directions
   
  -***avg_piat*** - Average packet interarrival time in both directions
   
  -***std_dev_piat*** - Packet interarrival time standard deviation in both directions 
   
  -***f_pktTotalCount*** - Total number of packets in the Forward direction
   
  -***f_octetTotalCount*** - Total of bytes exchanged in the forward direction focusing on the IP payload only 
   
  -***f_min_ps*** - Minimum packet size in forward direction
   
  -***f_max_ps*** - Maximum packet size in forward direction
   
  -***f_avg_ps*** - Average packet size in forward direction
   
  -***f_std_dev_ps*** - Packet size standard deviation in forward direction
   
  -***f_flowStart*** - Flow start time in seconds in the forward direction
   
  -***f_flowEnd*** - Flow end time in seconds in the forward direction
   
  -***f_flowDuration*** - Flow duration in seconds in the forward direction
   
  -***f_min_piat*** - Minimum packet interarrival time in the forward direction
   
  -***f_max_piat*** - Maximum packet interarrival time in the forward direction 
   
  -***f_avg_piat*** - Average packet interarrival time in the forward direction
   
  -***f_std_dev_piat*** - Packet interarrival time standard deviaton in the forward direction
   
  -***b_pktTotalCount*** - Total number of packets in the Forward direction 
   
  -***b_octetTotalCount*** - Total of bytes exchanged in the backward direction focusing on the IP payload only
   
  -***b_min_ps*** - Minimum packet size in backward direction
   
  -***b_max_ps*** - Maximum packet size in backward direction
   
  -***b_avg_ps*** - Average packet size in backward direction 
   
  -***b_std_dev_ps*** - Packet size standard deviation in backward direction 
   
  -***b_flowStart*** - Flow start time in seconds in the backward direction 
   
  -***b_flowEnd*** - Flow end time in the backward direction
   
  -***b_flowDuration*** - Flow duration in seconds in the backward direction
   
  -***b_min_piat*** - Minimum packet interarrival time in the backward direction
   
  -***b_max_piat*** - Maximum packet interarrival time in the backward directio
   
  -***b_avg_piat*** - Average packet interarrival time in the backward direction
   
  -***b_std_dev_piat*** - Packet interarrival time standard deviaton in the backward direction 
   
  -***flowEndReason*** -  The reason why the flow was expired and sent to the final array that will be converted to csv file - 0 inactive timeout expired - 1 active timeout expired - 2 forced expiration due to end of pcap file or live captured stopped - 3 FIN flag detected on both directions - 4 RST flag detected - 5 FIN Flag detected on one direction only and timer expired
   
  -***category*** - Category of the communication as delivered by nDPI
   
  -***application_protocol*** - Application protocol for the flow (e.g., TLS.Facebook, HTTP.YouTube, DNS.GMail, etc) detected by nDPI
    
