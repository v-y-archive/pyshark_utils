"""Flow class for aggregating packets into a Flow"""
from __future__ import print_function

from datetime import datetime, timedelta
from collections import defaultdict

# Local imports
from . import net_utils

# Helper methods
def flow_tuple(data):
	"""Tuple for flow (src, dst, sport, dport, proto)"""
	src = net_utils.inet_to_str(data["packet"].get("src")) if data["packet"].get("src") else None
	dst = net_utils.inet_to_str(data["packet"].get("dst")) if data["packet"].get("dst") else None
	sport = data["transport"].get("sport") if data.get("transport") else None
	dport = data["transport"].get("dport") if data.get("transport") else None
	proto = data["transport"].get("type") if data.get("transport") else data["packet"]["type"]
	return (src, dst, sport, dport, proto)

def _flow_tuple_reversed(f_tuple):
	"""Reversed tuple for flow (dst, src, dport, sport, proto)"""
	return (f_tuple[1], f_tuple[0], f_tuple[3], f_tuple[2], f_tuple[4])

class Flow(object):
	"""Flow object"""

	def __init__(self):
		"""Initialize Flow Class"""

		# Set up my meta data
		self.meta = {}
		self.meta["flow_id"] = None
		self.meta["src"] = None
		self.meta["dst"] = None
		self.meta["src_domain"] = None
		self.meta["dst_domain"] = None
		self.meta["sport"] = None
		self.meta["dport"] = None
		self.meta["protocol"] = None
		self.meta["direction"] = None
		self.meta["packet_list"] = []
		self.meta["payload"] = b""
		self.meta["start"] = None
		self.meta["end"] = None
		self.meta["state"] = "partial"
		self.meta["timeout"] = datetime.now() + timedelta(seconds=5)

	def add_packet(self, packet):
		"""Add a packet to this flow"""

		# First packet?
		if not self.meta["flow_id"]:
			self.meta["flow_id"] = flow_tuple(packet)
			self.meta["src"] = self.meta["flow_id"][0]
			self.meta["dst"] = self.meta["flow_id"][1]
			self.meta["src_domain"] = packet["packet"]["src_domain"]
			self.meta["dst_domain"] = packet["packet"]["dst_domain"]
			self.meta["sport"] = self.meta["flow_id"][2]
			self.meta["dport"] = self.meta["flow_id"][3]
			self.meta["protocol"] = self.meta["flow_id"][4]
			self.meta["direction"] = self._cts_or_stc(packet)
			self.meta["start"] = packet["timestamp"]
			self.meta["end"] = packet["timestamp"]

		# Add the packet
		self.meta["packet_list"].append(packet)
		if packet["timestamp"] < self.meta["start"]:
			self.meta["start"] = packet["timestamp"]
		if packet["timestamp"] > self.meta["end"]:
			self.meta["end"] = packet["timestamp"]

		# State of connection/flow
		if self.meta["protocol"] == "TCP":
			flags = packet["transport"]["flags"]
			if "syn" in flags:
				self.meta["state"] = "partial_syn"
				self.meta["direction"] = "CTS"
			elif "fin" in flags:
				# print("--- FIN RECEIVED %s ---"  % str(self.meta["flow_id))
				self.meta["state"] = "complete" if self.meta["state"] == "partial_syn" else "partial"
				self.meta["timeout"] = datetime.now() + timedelta(seconds=1)
			elif "syn_ack" in flags:
				self.meta["state"] = "partial_syn"
				self.meta["direction"] = "STC"
			elif "fin_ack"in flags:
				# print("--- FIN_ACK RECEIVED %s ---" % str(self.meta["flow_id))
				self.meta["state"] = "complete" if self.meta["state"] == "partial_syn" else "partial"
				self.meta["timeout"] = datetime.now() + timedelta(seconds=1)
			elif "rst" in flags:
				# print("--- RESET RECEIVED %s ---" % str(self.meta["flow_id))
				self.meta["state"] = "partial"
				self.meta["timeout"] = datetime.now() + timedelta(seconds=1)

		# Only collect UDP and TCP
		if self.meta["protocol"] not in ["UDP", "TCP"]:
			self.meta["timeout"] = datetime.now()

	def get_flow(self):
		"""Reassemble the flow and return all the info/data"""
		if self.meta["protocol"] == "TCP":
			self.meta["packet_list"].sort(key=lambda packet: packet["transport"]["seq"])
			for packet in self.meta["packet_list"]:
				self.meta["payload"] += packet["transport"]["data"]

		return self.meta

	def ready(self):
		"""Is this flow ready to go?"""
		return datetime.now() > self.meta["timeout"]

	@staticmethod
	def _cts_or_stc(data):
		"""Does the data look like a Client to Server (cts) or Server to Client (stc) traffic?"""

		# UDP/TCP
		if data["transport"]:

			# TCP flags
			if data["transport"]["type"] == "TCP":
				flags = data["transport"]["flags"]

				# Syn/Ack or fin/ack is a server response
				if "syn_ack" in flags or "fin_ack" in flags:
					return "STC"

				# Syn or fin is a client response
				if "syn" in flags or "fin" in flags:
					return "CTS"

			# Source Port/Destination Port
			if "sport" in data["transport"]:
				sport = data["transport"]["sport"]
				dport = data["transport"]["dport"]

				# High port talking to low port
				if dport < 1024 and sport > dport:
					return "CTS"

				# Low port talking to high port
				if sport < 1024 and sport < dport:
					return "STC"

				# Wow... guessing
				return "STC" if sport < dport else "CTS"

		# Internal/External
		if "src" in data["packet"] and "dst" in data["packet"]:
			src = net_utils.inet_to_str(data["packet"]["src"])
			dst = net_utils.inet_to_str(data["packet"]["dst"])

			# Internal talking to external?
			if net_utils.is_internal(src) and not net_utils.is_internal(dst):
				return "CTS"

			# External talking to internal?
			if net_utils.is_internal(dst) and not net_utils.is_internal(src):
				return "STC"

		# Okay we have no idea
		return "CTS"
