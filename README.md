# FlowLabeler

FlowLabeler is an application capable of processing IP packets either from pcap files or on a live capture mode to generate a csv file storing flow records containing bidirectional statistics and the application layer protocol (Youtube, Facebook, etc) using nDPI library.

It is important to mention that, this application is based on nfstream release 0.5.0 available on the following link:
                            
			    https://github.com/aouinizied/nfstream/tree/v0.5.0/nfstream
  
And also on FlowRecorder available on the following link:
                                      
				      https://github.com/drnpkr/flowRecorder

This application was created using **python 3.6.8**

# REQUIRED PYTHON MODULES

Modules that need to be installed (with pip for example):

-pip3 - For installing python modules
		                    	
					sudo apt-get install python3-pip

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
        
		sudo python3 main-file.py [operation mode (i or f)] [network-interface] [CSV FILE NAME] [ACTIVE TIMEOUT (SECONDS)] [INACTIVE TIMEOUT (SECONDS)]
  Examples:
        
			sudo python3 main-file.py i wlp0s20f3 /home/jsrojas/Test.csv 120 60
        		
			sudo python3 main-file.py i enp6s0f1 /home/jsrojas/Juan/Test.csv 120 60
        
**- FILE READER MODE:**
    
  The structure of the command is the following:
        
			python3 main-file.py [operation mode] [path-to-pcap-file] [CSV FILE NAME] [ACTIVE TIMEOUT (SECONDS)] [INACTIVE TIMEOUT (SECONDS)]
  Examples:
        
					python3 main-file.py f file.pcap Test.csv 120 60
        
			        python3 main-file.py f /home/jsrojas/Juan/Facebook-packets.pcap /home/Test.csv 120 60

