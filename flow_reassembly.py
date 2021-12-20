from itertools import groupby

import pyshark
from natsort import natsorted


# Network layers
LINK	= 0		# data-link layer (Ethernet)
INET	= 1		# internet layer (IP/IPv6)
TRANS	= 2		# transport layer (TCP/UDP)
TLS	= "tls"		# TLS layer
APP	= -1		# application layer (HTTP/HTTP2/QUIC)


def get_packet_layers(pkt):
	""" Get list of real layer protocols in packet except fucking trash layers. """
	pkt.layers = [layer for layer in pkt.layers if layer._layer_name != "fake-field-wrapper"]
	while len(pkt.layers) > 4 + (TLS in pkt):
		pkt.layers.pop()
	return pkt.layers

def get_transport_layer_streamid(pkt):
	""" Get TCP/UDP stream id. """
	transport = get_packet_layers(pkt)[TRANS]
	transport_protocol = transport._layer_name
	transport_streamid = transport.stream
	return f"{transport_protocol}:{transport_streamid}"

def get_app_layer_streamid(pkt):
	""" Get application layer protocol stream id if protocol is multistreaming. """
	transport_layer_streamid = get_transport_layer_streamid(pkt)
	application = get_packet_layers(pkt)[APP]
	application_protocol = application._layer_name
	application_streamid = application._all_fields.get(application_protocol+'.streamid')
	return f"{transport_layer_streamid}:{application_protocol}:{application_streamid}"

def transport_layer_reassembly(packets):
	""" Reassembly packets into flows by TCP/UDP stream id. """
	packets = natsorted(packets, key=lambda pkt: get_transport_layer_streamid(pkt))
	return groupby(packets, lambda pkt: get_transport_layer_streamid(pkt))

def app_layer_reassembly(packets):
	""" Reassembly packets into flows by application layer protocol stream id. """
	packets = natsorted(packets, key=lambda pkt: get_app_layer_streamid(pkt))
	return groupby(packets, lambda pkt: get_app_layer_streamid(pkt))

### Usage:
# def parse_pcap(pcap_file, sslkeylog_file):
# 	""" Decrypt the traffic with sslkeylog and reassembly flows. """
# 	packets = pyshark.FileCapture(
# 		input_file=pcap_file,
# 		override_prefs={"tls.keylog_file": sslkeylog_file},
# 		custom_parameters=["-2"])

# 	for transport_layer_streamid, transport_stream in transport_layer_reassembly(packets):
# 		for app_layer_streamid, session in app_layer_reassembly(transport_stream):
# 			for pkt in session:
# 				# Reassembled packets...