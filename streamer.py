#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lru import LRU  # for LRU streamer management
from collections import namedtuple
from observer import Observer
from classifier import NDPIClassifier, NFStreamClassifier
import socket
import json
import hashlib
import numpy as np
import threading
import concurrent.futures
import time
# For flows dictionary:
from collections import OrderedDict

###################################################GLOBAL VARIABLES AND FUNCTIONS###############################################################
""" flow key structure """
FlowKey = namedtuple('FlowKey', ['ip_src', 'ip_dst', 'src_port', 'dst_port', 'ip_protocol'])


""" flow export str representation """
flow_export_template = '''{ip_protocol},{ip_src},{src_port},{ip_dst},{dst_port},{ndpi_proto_num},\
{src_to_dst_pkts},{src_to_dst_bytes},{dst_to_src_pkts},{dst_to_src_bytes}'''


def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


def emergency_callback(key, value):
    """ Callback used for Streamer eviction method """
    if 'ndpi' in list(value.classifiers.keys()):
        value.ndpi_flow = None
    print("WARNING: Streamer capacity limit reached: lru flow entry dropped.")

def get_flow_key(pkt_info):
    """
    Generate a predictable bidirectional flow_hash for a TCP or UDP
    5-tuple. The hash is the same no matter which direction the
    traffic is travelling for all packets that are part of that flow.

    Pass this function a 5-tuple:
    (ip_src, ip_dst, ip_proto, src_port, dst_port)
    """
    # Calculate hash based on direction:
    # Flow in the Forward Direction
    if pkt_info.ip_src > pkt_info.ip_dst:
        flow_tuple = (pkt_info.ip_src, pkt_info.ip_dst, pkt_info.ip_protocol, pkt_info.src_port, pkt_info.dst_port)

    # Flow in the Backward Direction
    else:
        # Transpose IPs and port numbers for reverse packets:
        flow_tuple = (pkt_info.ip_dst, pkt_info.ip_src, pkt_info.ip_protocol, pkt_info.dst_port, pkt_info.src_port)

    hash_result = hashlib.md5()
    tuple_as_string = str(flow_tuple)
    hash_result.update(tuple_as_string.encode('utf-8'))
    return hash_result.hexdigest()

#########################################################################################################################################################
##################################################--FLOW CLASS--#########################################################################################
class Flow:
    """ Flow entry structure """
    def __init__(self, pkt_info, streamer_classifiers, streamer_metrics, flow_cache):
        #*************************************--FLOW IDENTIFIERS--****************************************
        # Obtain the flow key identifier using a md5 hash algorithm with the get_flow_hey() function
        self.key = get_flow_key(pkt_info)
        # Initialize the Source IP address in its integer form
        self.__ip_src_int = pkt_info.ip_src
        # Initialize the Source IP address in its byte form
        self.__ip_src_b = pkt_info.ip_src_b
        # Initialize the Source IP address in string form using the inet_to_str() function
        self.ip_src = inet_to_str(self.__ip_src_b)
        # Initialize the Source port of the flow
        self.src_port = pkt_info.src_port
        # Initialize the Destination IP address in its integer form
        self.__ip_dst_int = pkt_info.ip_dst
        # Initialize the Destination IP address in its byte form
        self.__ip_dst_b = pkt_info.ip_dst_b
        # Initialize the Destination IP address in string form using the inet_to_str() function
        self.ip_dst = inet_to_str(self.__ip_dst_b)
        # Initialize the destination port of the flow
        self.dst_port = pkt_info.dst_port
        # Initialize the transport protocol of the flow
        self.ip_protocol = pkt_info.ip_protocol
        #*****************************************************************************************************************
        #******************************--PACKET STATISTICS (BOTH DIRECTIONS)--********************************************
        # Initialize the total number of packets (in both directions)
        self.pktTotalCount = 0
        # Initialize the total number of bytes exchanged in both directions
        self.octetTotalCount = 0
        # Initialize the minimum packet size
        self.min_pkt_size = 0
        # Initialize the maximum packet size
        self.max_pkt_size = 0
        # Initialize the average packet size
        self.avg_pkt_size = 0
        # Initialize the standard deviation of the packet size
        self.std_dev_pkt_size = 0
        #*********************************************************************************************************
        #********************************--FLOW TIMERS--**********************************************************
        # Initialize the start time of the flow
        self.start_time = pkt_info.ts_float
        # Initialize the end time of the flow for now as the same start time
        self.end_time = pkt_info.ts_float
        # Initialize the Flow duration time of the flow
        self.flowDuration = 0
        # Initialize the minimum packet Inter-arrival time (both directions)
        self.min_piat = 0
        # Initialize the maximum packet Inter-arrival time (both directions)
        self.max_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.avg_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.std_dev_piat = 0
        # *********************************************************************************************************************
        #**********************************--FORWARD STATISTICS AND TIMERS--***************************************************
        # Initialize the number of packets in the Forward direction
        self.src_to_dst_pkts = 0
        # Initialize the total number of bytes exchanged in the Forward direction
        self.src_to_dst_bytes = 0
        # Initialize the minimum packet size
        self.f_min_pkt_size = 0
        # Initialize the maximum packet size
        self.f_max_pkt_size = 0
        # Initialize the average packet size
        self.f_avg_pkt_size = 0
        # Initialize the standard deviation of the packet size
        self.f_std_dev_pkt_size = 0
        # Initialize the start time of the flow
        self.f_start_time = 0
        # Initialize the end time of the flow for now as the same start time
        self.f_end_time = 0
        # Initialize the Flow duration time of the flow
        self.f_flowDuration = 0
        # Initialize the minimum packet Inter-arrival time (both directions)
        self.f_min_piat = 0
        # Initialize the maximum packet Inter-arrival time (both directions)
        self.f_max_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.f_avg_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.f_std_dev_piat = 0
        #***********************************************************************************************************************
        #**********************************--BACKWARD STATISTICS AND TIMERS--***************************************************
        # Initialize the number of packets in the Backward direction
        self.dst_to_src_pkts = 0
        # Initialize the total number of bytes exchanged in the Backward direction
        self.dst_to_src_bytes = 0
        # Initialize the minimum packet size
        self.b_min_pkt_size = 0
        # Initialize the maximum packet size
        self.b_max_pkt_size = 0
        # Initialize the average packet size
        self.b_avg_pkt_size = 0
        # Initialize the standard deviation of the packet size
        self.b_std_dev_pkt_size = 0
        # Initialize the start time of the flow
        self.b_start_time = 0
        # Initialize the end time of the flow for now as the same start time
        self.b_end_time = 0
        # Initialize the Flow duration time of the flow
        self.b_flowDuration = 0
        # Initialize the minimum packet Inter-arrival time (both directions)
        self.b_min_piat = 0
        # Initialize the maximum packet Inter-arrival time (both directions)
        self.b_max_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.b_avg_piat = 0
        # Initialize the average packet Inter-arrival time (both directions)
        self.b_std_dev_piat = 0
        #********************************************************************************************************************************

        # ********************************************OTHER ATTRIBUTES*******************************************************************
        # Initialize the export_reason as -1 for now (it can be 0 for inactve, 1 for active and 2 to flush to the final flows collection)
        self.export_reason = -1
        # Initialize a counter to detect the FIN flag on the flow
        self.FIN_flag_counter = 0
        # Initialize the attribute that will hold the timer for the FIN FLAG
        self.tcp_start_time = None
        # Initialize a counter to detect the ACK flag on the flow
        self.ACK_flag_counter = 0
        # Initialize the metrics dictionary where the user can add new flow metrics
        self.metrics = {}
        # Initialize the classifiers dictionary where the user can add his/her own classifiers
        # The nDPI classifier is declared and implemented by default
        self.classifiers = {}
        # This initializes all the flow metrics defined by the user to 0
        for metric_name in list(streamer_metrics.keys()):
            self.metrics[metric_name] = 0
        # This initializes all the classifiers and their flow structure in the NFStreamClassifier class
        # using the on_flow_init() function
        for name, classifier in streamer_classifiers.items():
            self.classifiers[classifier.name] = {}
            classifier.on_flow_init(self)
        # Python dictionaries to hold current and archived flow records
        self.flow_cache = flow_cache
        # *************************************************************************************************************************************


    #****************************************************** METHODS ***************************************************************************
    def create_new_flow_record(self, pkt_info, streamer_classifiers, streamer_metrics):
        # Obtain Flow Hash key
        flow_key = get_flow_key(pkt_info)
        # Get the position inside the of the flow inside the flow cache
        flow_dict = self.flow_cache[flow_key]

        #Set up the dictionary that will store the bidirectional statistics
        # Keys for the entire flow
        flow_dict['length'] = []
        flow_dict['times'] = []
        flow_dict['iats'] = []
        # Keys for the Forward direction
        flow_dict['f_length'] = []
        flow_dict['f_times'] = []
        flow_dict['f_iats'] = []
        # Keys for the Backward direction
        flow_dict['b_length'] = []
        flow_dict['b_times'] = []
        flow_dict['b_iats'] = []
        # Add all the packet information to the keys of the entire flow
        flow_dict['length'].append(pkt_info.size)
        flow_dict['times'].append(pkt_info.ts_float)

        # INITIALIZING FLOW STATISTICS
        self.pktTotalCount = 1
        self.octetTotalCount = pkt_info.size
        self.min_pkt_size = min(flow_dict['length'])
        self.max_pkt_size = max(flow_dict['length'])
        self.avg_pkt_size = self.octetTotalCount / self.pktTotalCount
        self.std_dev_pkt_size = np.std(flow_dict['length'])
        self.start_time = pkt_info.ts_float
        self.end_time = pkt_info.ts_float
        self.flowDuration = 0
        self.min_piat = 0
        self.max_piat = 0
        self.avg_piat = 0
        self.std_dev_piat = 0

        # INITIALIZING FORWARD STATISTICS
        if (self.__ip_src_int == pkt_info.ip_src and self.__ip_dst_int == pkt_info.ip_dst and
                self.src_port == pkt_info.src_port and self.dst_port == pkt_info.dst_port):
            # print("******PACKET IN FWD DIRECTION - UDATING FORWARD STATISTICS")
            # It is going in the forward direction, increase forward number of packets by 1
            self.src_to_dst_pkts += 1
            # Add the packet size to the total packet size of the flow
            self.src_to_dst_bytes += pkt_info.size

            # Store the size of the first packet:
            flow_dict['f_length'].append(pkt_info.size)
            # Set the min/max/avg/std_dev of packet sizes
            # (in case there will be no more packets belonging to the flow):
            self.f_min_pkt_size = pkt_info.size
            self.f_max_pkt_size = pkt_info.size
            self.f_avg_pkt_size = pkt_info.size
            self.f_std_dev_pkt_size = np.std(flow_dict['f_length'])

            # Store the timestamps of the packets:
            flow_dict['f_times'].append(pkt_info.ts_float)
            # store the flow start/end/duration
            self.f_start_time = pkt_info.ts_float
            self.f_end_time = pkt_info.ts_float
            self.f_flowDuration = 0
            # Set the min/max/avg/std_dev of packet-inter arrival times
            # (in case there will be no more packets belonging to the flow):
            self.f_min_piat = 0
            self.f_max_piat = 0
            self.f_avg_piat = 0
            self.f_std_dev_piat = 0

        #INITIALIZING BACKWARD STATISTICS
        else:
            # Increase the number of packets going from destination to source by 1
            self.dst_to_src_pkts += 1
            # Add the current packet size to the total packet size of the flow in the backward direction
            self.dst_to_src_bytes += pkt_info.size
            # Set direction of the packet to 1 (Backward direction) for the classifier
            pkt_info.direction = 1

            # Store the size of the first packet:
            flow_dict['b_length'].append(pkt_info.size)
            # Set the min/max/avg/std_dev of packet sizes
            # (in case there will be no more packets belonging to the flow):
            self.b_min_pkt_size = pkt_info.size
            self.b_max_pkt_size = pkt_info.size
            self.b_avg_pkt_size = pkt_info.size
            self.b_std_dev_pkt_size = np.std(flow_dict['b_length'])

            # Store the timestamps of the packets:
            flow_dict['b_times'].append(pkt_info.ts_float)
            # store the flow start/end/duration
            self.b_start_time = pkt_info.ts_float
            self.b_end_time = pkt_info.ts_float
            self.b_flowDuration = 0
            # Set the min/max/avg/std_dev of packet-inter arrival times
            # (in case there will be no more packets belonging to the flow):
            self.b_min_piat = 0
            self.b_max_piat = 0
            self.b_avg_piat = 0
            self.b_std_dev_piat = 0

        # Now let's send the packet information to each declared classifier
        # By default the nDPI classifier is declared and used to determine the application inside the flow
        for name, classifier in streamer_classifiers.items():
            classifier.on_flow_update(pkt_info, self)

        # And now let's calculate the additional metrics that were added in the streamer declaration
        metrics_names = list(streamer_metrics.keys())
        for metric_name in metrics_names:
            self.metrics[metric_name] = streamer_metrics[metric_name](pkt_info, self)

    def check_RST_flag(self, pkt_info):
        print("***CHECKING RST FLAG")
        # Check if the packet has an RST flag
        if (pkt_info.RST_flag):
            print("******RST FLAG FOUND")
            # This packet has an RST flag expired return 4
            self.export_reason = 4
            return self.export_reason
        else:
            # Return the export reason without modifying it
            print("******RST FLAG NOT FOUND - MOVING TO FIN FLAG CHECK")
            return self.export_reason

    def check_FIN_flag(self, pkt_info):
        print("***CHECKING FIN AND ACK FLAGS")
        # Does the packet has a FIN flag set?
        if (pkt_info.FIN_flag):
            print("******FIN FLAG FOUND - INCREASING COUNTER")
            # if it has a FIN flag increase the counter by 1
            self.FIN_flag_counter += 1
            print("******FIN FLAG COUNTER: ", self.FIN_flag_counter)
            # If the counter after the increasing is equal to 1 start FIN flag timer
            if(self.FIN_flag_counter == 1):
                # Start TCP TIMER
                print("******FIN FLAG COUNTER IS 1 - STARTING TIMER")
                self.tcp_start_time = time.time()
        # If the FIN flag counter is 2 and the packet has an ACK flag set export reason as 3 (flow completely finished)
        elif (pkt_info.ACK_flag and self.FIN_flag_counter >= 1):
            print("******ACK FLAG FOUND - INCREASING COUNTER")
            # if it has a FIN flag increase the counter by 1
            self.ACK_flag_counter += 1
            print("******ACK FLAG COUNTER: ", self.ACK_flag_counter)
        if(self.ACK_flag_counter == 2 and self.FIN_flag_counter == 2):
            print("******FIN FLAG COUNTER IS 2 AND ACK FLAG COUNTER IS 2")
            self.export_reason = 3
            return self.export_reason
        else:
            print("******FIN AND ACK FLAGS COUNTERS ARE NOT 2 - MOVING TO UPDATE STATISTICS")
            # Return the export reason without modifying it
            return self.export_reason

    def update_flow_statistics(self, pkt_info, streamer_classifiers, streamer_metrics):
        print("***UPDATING FLOW STATISTICS")
        # Find the flow record using the flow key
        flow_key = get_flow_key(pkt_info)
        flow_dict = self.flow_cache[flow_key]

        # Add the current packet values to the flow dictionary
        flow_dict['length'].append(pkt_info.size)
        flow_dict['times'].append(pkt_info.ts_float)
        # As we have now at least 2 packets in the flow, we can calculate the packet-inter-arrival-time.
        # We decrement the packet counter every single time, otherwise it would start from 2
        # The first piat will be the current timestamp minus the timestamp of the previous packet:
        flow_dict['iats'].append(flow_dict['times'][-1] - flow_dict['times'][-2])

        # UPDATING FLOW STATISTICS
        self.pktTotalCount += 1
        self.octetTotalCount += pkt_info.size
        self.min_pkt_size = min(flow_dict['length'])
        self.max_pkt_size = max(flow_dict['length'])
        self.avg_pkt_size = self.octetTotalCount / self.pktTotalCount
        self.std_dev_pkt_size = np.std(flow_dict['length'])
        self.end_time = pkt_info.ts_float
        self.flowDuration = self.end_time - self.start_time
        self.min_piat = min(flow_dict['iats'])
        self.max_piat = max(flow_dict['iats'])
        self.avg_piat = sum(flow_dict['iats']) / (self.pktTotalCount - 1)
        self.std_dev_piat = np.std(flow_dict['iats'])

        # UPDATING FORWARD STATISTICS
        if (self.__ip_src_int == pkt_info.ip_src and self.__ip_dst_int == pkt_info.ip_dst and
                self.src_port == pkt_info.src_port and self.dst_port == pkt_info.dst_port):
            # It is going in the forward direction, increase forward number of packets by 1
            self.src_to_dst_pkts += 1
            # Add the packet size to the total packet size of the flow
            self.src_to_dst_bytes += pkt_info.size

            # Store size of this packet in the forward direction dictionary:
            flow_dict['f_length'].append(pkt_info.size)
            # Update the min/max/avg/std_dev of the packet sizes:
            self.f_min_pkt_size = min(flow_dict['f_length'])
            self.f_max_pkt_size = max(flow_dict['f_length'])
            self.f_avg_pkt_size = self.src_to_dst_bytes / self.src_to_dst_pkts
            self.f_std_dev_pkt_size = np.std(flow_dict['f_length'])

            # Store the timestamps of the current packet:
            flow_dict['f_times'].append(pkt_info.ts_float)
            # Do inter-packet arrival time if have at least 2 packets:
            if (self.src_to_dst_pkts > 1):
                flow_dict['f_iats'].append(flow_dict['f_times'][-1] - flow_dict['f_times'][-2])
            # Update the flow end/duration (the start does not change)
            self.f_end_time = pkt_info.ts
            self.f_flowDuration = (pkt_info.ts_float - self.f_start_time)
            # at last update the min/max/avg/std_dev of packet-inter-arrival-times
            self.f_min_piat = min(flow_dict['f_iats'])
            self.f_max_piat = max(flow_dict['f_iats'])
            self.f_avg_piat = sum(flow_dict['f_iats']) / (self.src_to_dst_pkts - 1)
            self.f_std_dev_piat = np.std(flow_dict['f_iats'])

        # UPDATING BACKWARD STATISTICS
        else:
            # Note: this may be the first time we've seen backwards dir packet.
            # Increase the number of packets going from destination to source by 1
            self.dst_to_src_pkts += 1
            # Add the current packet size to the total packet size of the flow in the backward direction
            self.dst_to_src_bytes += pkt_info.size

            # Store size of this packet:
            flow_dict['b_length'].append(pkt_info.size)
            # Update the min/max/avg/std_dev of the packet sizes:
            self.b_min_pkt_size = min(flow_dict['b_length'])
            self.b_max_pkt_size = max(flow_dict['b_length'])
            self.b_avg_pkt_size = self.dst_to_src_bytes / self.dst_to_src_pkts
            self.b_std_dev_pkt_size = np.std(flow_dict['b_length'])

            # Store the timestamps of the newly captured packets:
            flow_dict['b_times'].append(pkt_info.ts_float)
            # Do inter-packet arrival time if have at least 2 packets:
            if (self.dst_to_src_pkts < 2):
                # First time, so set some stuff:
                self.b_start_time = pkt_info.ts_float
                self.b_end_time = pkt_info.ts_float
                self.b_flowDuration = 0
            else:
                # Not first time seen a packet in the backward direction:
                flow_dict['b_iats'].append(flow_dict['b_times'][-1] - flow_dict['b_times'][-2])
                self.b_end_time = pkt_info.ts_float
                self.b_flowDuration = (pkt_info.ts - self.b_start_time)
                # Update the min/max/avg/std_dev of packet-inter-arrival-times:
                self.b_min_piat = min(flow_dict['b_iats'])
                self.b_max_piat = max(flow_dict['b_iats'])
                self.b_avg_piat = sum(flow_dict['b_iats']) / (self.dst_to_src_pkts - 1)
                self.b_std_dev_piat = np.std(flow_dict['b_iats'])

        for name, classifier in streamer_classifiers.items():
            classifier.on_flow_update(pkt_info, self)

        # And now let's calculate the additional metrics that were added in the streamer declaration
        metrics_names = list(streamer_metrics.keys())
        for metric_name in metrics_names:
            self.metrics[metric_name] = streamer_metrics[metric_name](pkt_info, self)


    def start_threads_and_update_statistics(self, pkt_info, active_timeout, streamer_classifiers, streamer_metrics, flows_LRU):
        # Store previous packet end time to check active timeout after updating statistics
        current_time = time.time()
        previous_end_time = self.end_time

        # Check if the packet has an RST flag
        self.check_RST_flag(pkt_info)

        # Start the thread to check if the packet has a FIN flag with a ThreadPoolExecutor
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            FIN_flag_thread = executor.submit(self.check_FIN_flag, pkt_info)
            return_value_FIN_flag = FIN_flag_thread.result()

        # Update bidirectional statistics
        self.update_flow_statistics(pkt_info, streamer_classifiers, streamer_metrics)

        # Check FIN flag timer in case it has beet started on a previous thread
        if ((self.tcp_start_time != None) and ((current_time - self.tcp_start_time) > 2) and
                (flows_LRU[self.key].FIN_flag_counter == 1)):
            self.export_reason = 5

        # Return the current export reason
        return self.export_reason

    def __str__(self):
        metrics = {'ip_src': self.ip_src,
                   'src_port': self.src_port,
                   'ip_dst': self.ip_dst,
                   'dst_port': self.dst_port,
                   'ip_protocol': self.ip_protocol,
                   'src_to_dst_pkts': self.src_to_dst_pkts,
                   'dst_to_src_pkts': self.dst_to_src_pkts,
                   'src_to_dst_bytes': self.src_to_dst_bytes,
                   'dst_to_src_bytes': self.dst_to_src_bytes,
                   'start_time': self.start_time,
                   'end_time': self.end_time,
                   'export_reason': self.export_reason,
                   'FIN_flag_counter': self.FIN_flag_counter
                   }
        return json.dumps({**self.metrics, **metrics})

#######################################################################################################################################################

######################################################--STREAMER CLASS--##############################################################################
class Streamer:
    """ streamer for flows management """
    num_streamers = 0

    def __init__(self, source=None, capacity=128000, active_timeout=120, inactive_timeout=60,
                 user_metrics=None, user_classifiers=None, enable_ndpi=True):

        Streamer.num_streamers += 1
        self.__exports = []
        self.source = source
        self.__flows = LRU(capacity, callback=emergency_callback)  # LRU cache
        self._capacity = self.__flows.get_size()  # Streamer capacity (default: 128000)
        self.active_timeout = active_timeout  # expiration active timeout
        self.inactive_timeout = inactive_timeout  # expiration inactive timeout
        self.current_flows = 0  # counter for stored flows
        self.flows_number = 0
        self.current_tick = 0  # current timestamp
        self.processed_packets = 0  # current timestamp
        # Python dictionaries to hold current and archived flow records
        self.flow_cache = OrderedDict()
        self.inactive_timer_event = threading.Event()
        self.active_timer_event = threading.Event()
        self.user_classifiers = {}
        if user_classifiers is not None:
            try:
                classifier_iterator = iter(user_classifiers)
                for classifier in classifier_iterator:
                    if isinstance(classifier, NFStreamClassifier):
                        self.user_classifiers[classifier.name] = classifier
            except TypeError:
                self.user_classifiers[user_classifiers.name] = user_classifiers
        self.user_metrics = {}
        if enable_ndpi:
            ndpi_classifier = NDPIClassifier('ndpi')
            self.user_classifiers[ndpi_classifier.name] = ndpi_classifier
        if user_metrics is not None:
            self.user_metrics = user_metrics

    def _get_capacity(self):
        """ getter for capacity attribute """
        return self.__flows.get_size()

    def _set_capacity(self, new_size):
        """ setter for capacity size attribute """
        return self.__flows.set_size(new_size)

    capacity = property(_get_capacity, _set_capacity)

    def terminate(self):
        """ terminate all entries in Streamer """
        remaining_flows = True
        while remaining_flows:
            try:
                key, value = self.__flows.peek_last_item()
                value.export_reason = 2
                self.exporter(value)
            except TypeError:
                remaining_flows = False

        for classifier_name, classifier in self.user_classifiers.items():
            self.user_classifiers[classifier_name].on_exit()

    def exporter(self, flow):
        """ export method for a flow trigger_type:0(inactive), 1(active), 2(flush) """
        # Look for the flow in the created classifiers
        for classifier_name, classifier in self.user_classifiers.items():
            # Terminate the flow in the respective classifiers
            self.user_classifiers[classifier_name].on_flow_terminate(flow)
        # Delete the flow register from the active flows collection
        del self.__flows[flow.key]
        # Decrease the number of active flows by 1
        self.current_flows -= 1
        # Add the expired flow register to the final flows collection
        self.__exports.append(flow)

    def inactive_watcher(self, inactive_timer_event):
        """ inactive expiration management """
        if not inactive_timer_event.is_set():
            threading.Timer(1, self.inactive_watcher, [inactive_timer_event]).start()
            remaining_inactives = True
            # While there are inactive flow registers
            while remaining_inactives:
                try:
                    # Obtain the last flow register (Least Recently Used - LRU) in the variable value using its key
                    key, value = self.__flows.peek_last_item()
                    # Has the flow exceeded the inactive timeout (1 minute)?
                    if (self.current_tick - value.end_time) >= (self.inactive_timeout*1000):
                        # Set export reason to 0 (inactive) in the flow
                        value.export_reason = 0
                        # Export the flow to the final flows collection
                        self.exporter(value)
                # There are no flows that can be declared inactive yet
                    else:
                        # Stop the inactive watcher until it is called again
                        remaining_inactives = False
                except TypeError:
                    remaining_inactives = False

    def active_watcher(self, active_timer_event):
        # Obtaining all the flows stored in the LRU
        active_flows = self.__flows.values()
        # If the time set on the event has expired check if the active timeout has expired
        if not active_timer_event.is_set():
            threading.Timer(1, self.active_watcher, [active_timer_event]).start()
            try:
                # Iterate through the active flows and check the active timeout
                for i, value in enumerate(active_flows):
                    # Is the active timeout expired?
                    if (self.current_tick - value.end_time) >= (self.active_timeout * 1000):
                        # Set export reason to 1 (active) in the flow
                        value.export_reason = 1
                        # Export the flow to the final flows collection
                        self.exporter(value)
                    else:
                        # If the active timeout has not expired continue with the next flow
                        continue
            except (KeyboardInterrupt, SystemExit):
                print("PROCESSING INTERRUPTED")

    def consume(self, pkt_info):
        """ consume a packet and update Streamer status """
        # increment total processed packet counter
        print("\n****************STARTING PACKET ANALYSIS****************************")
        self.processed_packets += 1
        print("CURRENT PROCESSED PACKETS: ",self.processed_packets)

        # Obtain a flow hash key for identification of the flow
        key = get_flow_key(pkt_info)

        # Is this packet from a registered flow in the LRU?
        if key in self.__flows:
            print("FLOW FOUND IN LRU - CHECKING FLAGS AND UPDATING - HASH:", key)
            # Checking current status of the flow that the packet belongs to
            # -1 active flow - 0 inactive timeout expired - 1 active timeout expired - 2 flow still active but flushed from the LRU
            # 3 FIN flags and ACK flag detected - 4 RST flag detected - 5 FIN flag timeout expired
            flow_status = self.__flows[key].start_threads_and_update_statistics(pkt_info, self.active_timeout, self.user_classifiers, self.user_metrics, self.__flows)

            #Has the active timeout of the flow register expired (2 minutes)?
            if (flow_status == 1):
                print("ACTIVE TIMEOUT EXPIRED - EXPORTING FLOW")
                # Export the old flow register to the final collection and terminate this flow process on the specified classifier
                self.exporter(self.__flows[key])
                # Create a new flow register for the current packet
                flow = Flow(pkt_info, self.user_classifiers, self.user_metrics, self.flow_cache)
                # Add the new flow to the active flows collection using the same Hash key
                self.__flows[flow.key] = flow
                # Create the entry on the flow_cache with the flow key
                del self.flow_cache[flow.key]
                self.flow_cache[flow.key] = {}
                # Update the flow status on the collection
                flow.create_new_flow_record(pkt_info, self.user_classifiers, self.user_metrics)
            if (flow_status == 3): # FIN FLAG DETECTED IN BOTH DIRECTIONS - EXPORTING FLOW
                print("FOUND FIN AND ACK FLAGS IN BOTH DIRECTIONS - EXPORTING FLOW")
                self.exporter(self.__flows[key])
            if (flow_status == 4): # RST FLAG FOUND - UPDATING BIDIRECTIONAL STATISTICS - EXPORTING FLOW
                print("FOUND RST FLAG - EXPORTING FLOW")
                self.exporter(self.__flows[key])
            if (flow_status == 5): # FIN FLAG TIMER EXPIRED
                print("FIN FLAG TIMER EXPIRED - EXPORTING FLOW")
                self.exporter(self.__flows[key])

        # This packet belongs to a new flow
        else:
            print("PACKET OF A NEW FLOW FOUND - CREATING REGISTER WITH HASH:", key)
            # Increase the count of current active flows
            # Update flow counters
            self.current_flows += 1
            self.flows_number += 1
            # Create the new flow object
            flow = Flow(pkt_info, self.user_classifiers, self.user_metrics, self.flow_cache)
            # Add this new flow register to the LRU
            self.__flows[flow.key] = flow
            # Create the entry on the flow_cache with the flow key to store bidirectional statistics if there are more packets
            self.flow_cache[flow.key] = {}
            # Create the new bidirectional flow record
            flow.create_new_flow_record(pkt_info, self.user_classifiers, self.user_metrics)
            # Set the current start time on the streamer timer to keep control of the inactive flows
            self.current_tick = flow.start_time
        print("****************MOVING TO NEXT PACKET****************************")

    def __iter__(self):
        # Create the packet information generator
        pkt_info_gen = Observer(source=self.source)
        # Extract each packet information from the network interface or pcap file
        for pkt_info in pkt_info_gen:
            if pkt_info is not None:
                # Check if the packet belongs to an existent flow or create a new one
                self.consume(pkt_info)
                for export in self.__exports:
                    yield export
                self.__exports = []
        # Terminate the streamer
        self.terminate()
        for export in self.__exports:
            yield export
        self.   __exports = []
#######################################################################################################################################################
