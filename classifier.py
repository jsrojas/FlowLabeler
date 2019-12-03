from ndpi_bindings import ndpi, NDPI_PROTOCOL_BITMASK, ndpi_flow_struct, ndpi_protocol, ndpi_id_struct
from ctypes import pointer, memset, sizeof, cast, c_char_p, c_void_p, POINTER, c_uint8, addressof


########################################################--CLASSIFIER CLASS--##############################################################################3
# This is the class that will be inherited by the other declared classifiers
class NFStreamClassifier:
    def __init__(self, name):
        # Initialize the name of the classifier in order to be easily found
        self.name = name

    def on_flow_init(self, flow):
        return

    def on_flow_update(self, packet_information, flow):
        return

    def on_flow_terminate(self, flow):
        return

    def on_exit(self):
        return

# This is the class that implements a classifier using the nDPI library through ctypes module to perform deep packet inspection and obtain the application of the flow
# This class inherits from the NFStreamClassifier class and overrides its methods with the needed implementation
class NDPIClassifier(NFStreamClassifier):

    #This method initializes the object with all the attributes needed by the nDPI library
    def __init__(self, name):
        # This initializes the name of the classifier
        NFStreamClassifier.__init__(self, name)
        # This initializes the nDPI detection module with its needed BITMASK
        self.mod = ndpi.ndpi_init_detection_module()
        all = NDPI_PROTOCOL_BITMASK()
        ndpi.ndpi_wrap_NDPI_BITMASK_SET_ALL(pointer(all))
        ndpi.ndpi_set_protocol_detection_bitmask2(self.mod, pointer(all))
        # This initializes the maximum number of UDP dissected packets
        self.max_num_udp_dissected_pkts = 16
        # This initializes the maximum number of TCP dissected packets
        self.max_num_tcp_dissected_pkts = 10

    # This function overrides the one inherited from NFStreamClassifier class and initializes the nDPI flow structure
    def on_flow_init(self, flow):
        flow.classifiers[self.name]['ndpi_flow'] = pointer(ndpi_flow_struct())
        memset(flow.classifiers[self.name]['ndpi_flow'], 0, sizeof(ndpi_flow_struct))
        flow.classifiers[self.name]['detected_protocol'] = ndpi_protocol()
        flow.classifiers[self.name]['detection_completed'] = 0
        flow.classifiers[self.name]['src_id'] = pointer(ndpi_id_struct())
        flow.classifiers[self.name]['dst_id'] = pointer(ndpi_id_struct())
        flow.classifiers[self.name]['application_name'] = ''
        flow.classifiers[self.name]['category_name'] = ''

    # This function overrides the one inherited from NFStreamClassifier class and performs the DPI on the received packet
    def on_flow_update(self, packet_information, flow):
        # Is the detection of the application completed?
        if flow.classifiers[self.name]['detection_completed'] == 0:
            # It is not, then process the current packet with nDPI library
            flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_process_packet(
                self.mod,
                flow.classifiers[self.name]['ndpi_flow'],
                cast(cast(c_char_p(packet_information.content), c_void_p), POINTER(c_uint8)),
                len(packet_information.content),
                packet_information.ts,
                flow.classifiers[self.name]['src_id'],
                flow.classifiers[self.name]['dst_id']
            )
            # Initialize a "valid" variable that will be set as True if the total number of exchanged packets (in both directions) in the flow
            # is bigger than 10 for TCP or if it is bigger than 16 packets for UDP
            valid = False
            # Is the transport protocol TCP?
            if flow.ip_protocol == 6:
                # Check if the total quantity of packets (in both directions) is bigger than 10
                # and set valid to True if it is the case
                valid = (flow.src_to_dst_pkts + flow.dst_to_src_pkts) > self.max_num_tcp_dissected_pkts
            # It is not TCP, then is the transport protocol UDP?
            elif flow.ip_protocol == 17:
                # Check if the total quantity of packets (in both directions) is bigger than 16
                # and set valid to True if it is the case
                valid = (flow.src_to_dst_pkts + flow.dst_to_src_pkts) > self.max_num_udp_dissected_pkts
            # Is valid is TRUE or the detected application protocol is different from UNKNOWN
            if valid or flow.classifiers[self.name]['detected_protocol'].app_protocol != 0:
                # Is valid is TRUE or the detected master protocol is different from TLS (Transport Layer Security)
                if valid or flow.classifiers[self.name]['detected_protocol'].master_protocol != 91:
                    # The classification process of the packet is completed, set to 1
                    flow.classifiers[self.name]['detection_completed'] = 1
                    # Is the detected application protocol UNKOWN (number 0)
                    if flow.classifiers[self.name]['detected_protocol'].app_protocol == 0:
                        # Stop the detection, the nDPI library could not detect the application protocol
                        flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_giveup(
                            self.mod,
                            flow.classifiers[self.name]['ndpi_flow'],
                            1,
                            cast(addressof(c_uint8(0)), POINTER(c_uint8))
                        )
        # HERE you can change flow.export_reason to a value > 2 and the flow will be terminated automatically

    def on_flow_terminate(self, flow):
        if flow.classifiers[self.name]['detected_protocol'].app_protocol == 0:
            flow.classifiers[self.name]['detected_protocol'] = ndpi.ndpi_detection_giveup(
                self.mod,
                flow.classifiers[self.name]['ndpi_flow'],
                1,
                cast(addressof(c_uint8(0)), POINTER(c_uint8))
            )
        master_name = cast(ndpi.ndpi_get_proto_name(self.mod,
                                                    flow.classifiers[self.name]['detected_protocol'].master_protocol),
                           c_char_p).value.decode('utf-8')
        app_name = cast(ndpi.ndpi_get_proto_name(self.mod,
                                                 flow.classifiers[self.name]['detected_protocol'].app_protocol),
                        c_char_p).value.decode('utf-8')
        category_name = cast(ndpi.ndpi_category_get_name(self.mod,
                                                         flow.classifiers[self.name]['detected_protocol'].category),
                             c_char_p).value.decode('utf-8')
        flow.classifiers[self.name]['application_name'] = master_name + '.' + app_name
        flow.classifiers[self.name]['category_name'] = category_name
        flow.classifiers[self.name]['app_id'] = flow.classifiers[self.name]['detected_protocol'].app_protocol
        flow.classifiers[self.name]['master_id'] = flow.classifiers[self.name]['detected_protocol'].master_protocol
        flow.classifiers[self.name]['ndpi_flow'] = None
        # Now we do move some values to flow.metrics just to print purpose. If you are implementing your magic
        # classifier, just do flow.classifiers['name_of_your_classifier]['name_of_your_feature']
        # if we move it before, it will trigger metrics callback.
        flow.metrics['application_name'] = flow.classifiers[self.name]['application_name']
        flow.metrics['category_name'] = flow.classifiers[self.name]['category_name']

    def on_exit(self):
        ndpi.ndpi_exit_detection_module(self.mod)

#########################################################################################################################################################