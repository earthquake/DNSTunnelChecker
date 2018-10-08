# MIT License

# Copyright (c) 2017-2018 Balazs Bucsay

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import sys

if "dns_proto.py" in sys.argv[0]:
	print("[-] Instead of poking around just try: python xfltreat.py --help")
	sys.exit(-1)

import struct
import socket
import math
import time

class DNS_Proto():
	def __init__(self):
		self.edns = 0
		self.response_codes = ["", 
			"Query error: Format error - the DNS server does not support this format (maybe the query was too long)",
			"Query error: Server failure - the DNS server failed (maybe the response was too long, or the server is not running)",
			"Burning packets on server side",
			"Query error: Not implemented - the DNS does not support the record type",
			"Query error: Refused - DNS server is not willing to answer. (can the DNS server be used as relay?)",
			"Other error, malformed request/response, etc."]

		self.RR_types = {
			0 : ["", None, None, None, None], # answer with no answers
			1 : ["A", self.build_record_A, self.pack_record_id, self.unpack_record_hostname, self.calc_max_throughput_A],
			2 : ["NS", self.build_record_NS, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    3 : ["MD", None, None, None, None],
		    4 : ["MF", None, None, None, None],
		    5 : ["CNAME", self.build_record_CNAME, self.pack_record_hostname, self.unpack_record_hostname, self.calc_max_throughput_CNAME],
		    6 : ["SOA", self.build_record_SOA, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    7 : ["MB", None, None, None, None],
		    8 : ["MG", None, None, None, None],
		    9 : ["MR", None, None, None, None],
		    10 : ["NULL", self.build_record_NULL, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    11 : ["WKS", None, None, None, None],
		    12 : ["PTR", None, None, None, None],
		    13 : ["HINFO", None, None, None, None],
		    14 : ["MINFO", None, None, None, None],
		    15 : ["MX", self.build_record_MX, self.pack_record_hostname, self.unpack_record_hostname, None],
		    16 : ["TXT", self.build_record_TXT, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    17 : ["RP", None, None, None, None],
		    18 : ["AFSDB", None, None, None, None],
		    19 : ["X25", None, None, None, None],
		    20 : ["ISDN", None, None, None, None],
		    21 : ["RT", None, None, None, None],
		    22 : ["NSAP", None, None, None, None],
		    23 : ["NSAP-PTR", None, None, None, None],
		    24 : ["SIG", None, None, None, None],
		    25 : ["KEY", None, None, None, None],
		    26 : ["PX", None, None, None, None],
		    27 : ["GPOS", None, None, None, None],
		    28 : ["AAAA", self.build_record_AAAA, self.pack_record_id, self.unpack_record_hostname, None],
		    29 : ["LOC", None, None, None, None],
		    30 : ["NXT", None, None, None, None],
		    31 : ["EID", None, None, None, None],
		    32 : ["NIMLOC", None, None, None, None],
		    33 : ["SRV", self.build_record_SRV, self.pack_record_hostname, self.unpack_record_hostname, None],
		    34 : ["ATMA", None, None, None, None],
		    35 : ["NAPTR", None, None, None, None],
		    36 : ["KX", None, None, None, None],
		    37 : ["CERT", None, None, None, None],
		    38 : ["A6", None, None, None, None],
		    39 : ["DNAME", None, None, None, None],
		    40 : ["SINK", None, None, None, None],
		    41 : ["OPT", None, None, None, None],
		    42 : ["APL", None, None, None, None],
		    43 : ["DS", None, None, None, None],
		    44 : ["SSHFP", None, None, None, None],
		    45 : ["IPSECKEY", None, None, None, None],
		    46 : ["RRSIG", self.build_record_RRSIG, self.pack_record_id, None, None],
		    47 : ["NSEC", None, None, None, None],
		    48 : ["DNSKEY", self.build_record_DNSKEY, self.pack_record_id, None, None],
		    49 : ["DHCID", None, None, None, None],
		    50 : ["NSEC3", None, None, None, None],
		    51 : ["NSEC3PARAM", None, None, None, None],
		    52 : ["TLSA", None, None, None, None],
		    53 : ["SMIMEA", None, None, None, None],
		    #54 : ["Unassigned", None, None, None, None],
		    55 : ["HIP", None, None, None, None],
		    56 : ["NINFO", None, None, None, None],
		    57 : ["RKEY", None, None, None, None],
		    58 : ["TALINK", None, None, None, None],
		    59 : ["CDS", None, None, None, None],
		    60 : ["CDNSKEY", None, None, None, None],
		    61 : ["OPENPGPKEY", None, None, None, None],
		    62 : ["CSYNC", None, None, None, None],
		    ## TEST
		    #63-98 : ["Unassigned", None, None, None, None],
		    99 : ["SPF", None, None, None, None],
		    100 : ["UINFO", None, None, None, None],
		    101 : ["UID", None, None, None, None],
		    102 : ["GID", None, None, None, None],
		    103 : ["UNSPEC", None, None, None, None],
		    104 : ["NID", None, None, None, None],
		    105 : ["L32", None, None, None, None],
		    106 : ["L64", None, None, None, None],
		    107 : ["LP", None, None, None, None],
		    108 : ["EUI48", None, None, None, None],
		    109 : ["EUI64", None, None, None, None],
		    ## TEST
		    #110-248 : ["Unassigned", None, None, None, None],
		    249 : ["TKEY", None, None, None, None],
		    250 : ["TSIG", None, None, None, None],
		    251 : ["IXFR", None, None, None, None],
		    252 : ["AXFR", None, None, None, None],
		    253 : ["MAILB", None, None, None, None],
		    254 : ["MAILA", None, None, None, None],
		    255 : ["*", self.build_record_ANY, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id],
		    256 : ["URI", None, None, None, None],
		    257 : ["CAA", None, None, None, None],
		    258 : ["AVC", None, None, None, None],
		    ## TEST
		    #259-32767 : ["Unassigned", None, None, None, None],
		    32768 : ["TA", None, None, None, None],
		    32769 : ["DLV", None, None, None, None],
		    65399 : ["PRIVATE", self.build_record_PRIVATE, self.pack_record_id, self.unpack_record_id, self.calc_max_throughput_id]
		    ## TEST
			#65280-65534 : ["Private use", None, None, None, None],
			## TEST
		    #65535 : "Reserved"
		}
		return

	def set_edns(self, value):
		self.edns = value

	def calc_max_throughput_id(self, max_length, hostname, overhead, encoding_class):
		return encoding_class.get_maximum_length(max_length - overhead)

	def pack_record_id(self, data):
		return data

	def unpack_record_id(self, data):
		return data

	def pack_record_hostname(self, data):
		hostname = ""
		for j in range(0,int(math.ceil(float(len(data))/63.0))):
			hostname += data[j*63:(j+1)*63]+"."

		return hostname

	def unpack_record_hostname(self, data):
		hostname = self.hostnamebin_to_hostname(data)[1].replace(".", "")

		return hostname.replace(".", "")

	def calc_max_throughput_A(self, max_length, hostname, overhead, encoding_class):
		# max - len("hostname.") - 1 - overhead - plus dots
		max_length -= len(hostname) + 1
		cap = 0
		while max_length > 64:
			cap += 63
			max_length -= 64
		cap += max_length - 1

		return encoding_class.get_maximum_length(cap) - overhead

	def build_record_OPT(self):
		return struct.pack(">BHHBBHH", 0x00, 41, 4096, 0, 0, 0x8000, 0)

	def build_record_A(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		#answers = struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[2]) 
		answers = ""
		for i in xrange(record[3]):
			answers += struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + record[2][i]

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_AAAA(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		#answers = struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[2]) 
		answers = ""
		for i in xrange(record[3]):
			answers += struct.pack(">HHHIH", 0xc00c, 28, 1, 5, 16) + record[2][i]

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NS(self, record):
		additional_record_num = 0
		additional_records = ""
		compress_hostname = self.hostname_to_hostnamebin(record[2])

		answer_num = 1
		answers = struct.pack(">HHHIH", 0xc00c, 2, 1, 3600, len(compress_hostname)) + compress_hostname
		
		#additional_record_num = 1
		#additional_records = compress_hostname + struct.pack(">HHIH", 1, 1, 5, 4) + socket.inet_aton("1.1.1.1")

		return (answer_num, answers, additional_record_num, additional_records)

	def calc_max_throughput_CNAME(self, max_length, hostname, overhead, encoding_class):
		# -1 for the zero byte at the end
		max_length -= 1
		cap = 0
		while max_length > 64:
			cap += 63
			max_length -= 64
		cap += max_length - 1

		return encoding_class.get_maximum_length(cap) - overhead

	def build_record_CNAME(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		answers = ""
		for i in xrange(record[3]):	
			compress_hostname = self.hostname_to_hostnamebin(record[2][i])
			answers += struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_MX(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		answers = ""
		for i in xrange(record[3]):	
			compress_hostname = self.hostname_to_hostnamebin(record[2][i])
			answers += struct.pack(">HHHIHH", 0xc00c, 15, 1, 5, len(compress_hostname)+2, 10*i+10) + compress_hostname

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_SRV(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		answers = ""
		for i in xrange(record[3]):	
			compress_hostname = self.hostname_to_hostnamebin(record[2][i])
			answers += struct.pack(">HHHIHHHH", 0xc00c, 33, 1, 5, len(compress_hostname)+6, 10*i+10, 20*i+10, 1337) + compress_hostname

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_DNSKEY(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		answers = ""
		for i in xrange(record[3]):	
			answers += struct.pack(">HHHIHHBB", 0xc00c, 48, 1, 5, len(record[2][i])+4, 0x0100, 3, 8) + record[2][i]

		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_RRSIG(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]
		answers = ""
		for i in xrange(record[3]):	
			compress_hostname = self.hostname_to_hostnamebin(record[4])
			answers += struct.pack(">HHHIHHBBIIIH", 0xc00c, 46, 1, 5, len(compress_hostname + record[2][i])+18, 16, 10, 2, 5, int(time.time()) + 3600*36, 
				int(time.time()) + 3600*12, 31005) + compress_hostname + record[2][i]

		return (answer_num, answers, additional_record_num, additional_records)


	def build_record_ANY(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = ""

		answer_num = 2
		answers =  struct.pack(">HHHIH", 0xc00c, 5, 1, 5, len(compress_hostname)) + compress_hostname
		answers += struct.pack(">HHHIH", 0xc00c, 1, 1, 5, 4) + socket.inet_aton(record[3])
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_SOA(self, record):
		compress_hostname = self.hostname_to_hostnamebin(record[2])
		additional_record_num = 0
		additional_records = ""

		answer_num = 1
		#data = self.hostname_to_hostnamebin(record[2]) + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])
		data = compress_hostname + self.hostname_to_hostnamebin(record[3]) + struct.pack(">IIIII", record[4], record[5], record[6], record[7], record[8])

		answers = struct.pack(">HHHIH", 0xc00c, 6, 1, 5, len(data)) + data
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_NULL(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]

		answers = ""
		for i in xrange(record[3]):
			answers += struct.pack(">HHHIH", 0xc00c, 10, 1, 0, len(record[2][i])) + record[2][i]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_PRIVATE(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]

		answers = ""
		for i in xrange(record[3]):
			answers += struct.pack(">HHHIH", 0xc00c, 65399, 1, 0, len(record[2][i])) + record[2][i]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def build_record_TXT(self, record):
		additional_record_num = 0
		additional_records = ""

		answer_num = record[3]

		answers = ""
		for i in xrange(record[3]):
			answers += struct.pack(">HHHIHB", 0xc00c, 16, 1, 0, len(record[2][i])+1, len(record[2][i])) + record[2][i]
		
		return (answer_num, answers, additional_record_num, additional_records)

	def get_RR_type(self, num):
		if num in self.RR_types:
			return self.RR_types[num]
		else:
			common.internal_print("Error: requested RR type was not in the list.", 1, -1)
			return None

	def reverse_RR_type(self, RRtype):
		for i in self.RR_types:
			if self.RR_types[i][0] == RRtype:
				return self.RR_types[i]

		return 0

	def reverse_RR_type_num(self, RRtype):
		for i in self.RR_types:
			if self.RR_types[i][0] == RRtype:
				return i

		return 0


	def get_record(self, short_hostname, qtype, zone):
		if qtype not in self.RR_types:
			return None

		for i in xrange(len(zone)):
			if (zone[i][0] == self.RR_types[qtype][0]) and (zone[i][1] == short_hostname):
				return zone[i]

		return None

	def hostname_to_hostnamebin(self, hostname):
		if hostname[len(hostname)-1:len(hostname)] != ".":
			hostname += "."
		i = 0

		hostnamebin = ""
		while not hostname[i:].find(".") == -1:
			hostnamebin += struct.pack("B", hostname[i:].find(".")) + hostname[i:i+hostname[i:].find(".")]
			i = i + hostname[i:].find(".")+1

		hostnamebin += "\x00"

		return hostnamebin

	def hostnamebin_to_hostname(self, hostnamebin):
		hostname = ""
		i = 0
		length = 0

		while True:
			if len(hostnamebin) > i:
				l = struct.unpack("B",hostnamebin[i:i+1])[0]
				if l > 63:
					length += 2
					break
				if l == 0:
					length += 1
					break
				hostname += hostnamebin[i+1:i+1+l] + "."
				length += l + 1
				i = i + l + 1
			else:
				break

		return (length, hostname)

	def is_valid_dns(self, msg, hostname):
		# check if the message's len is more than the minimum
		# header + base hostname + type+class
		if len(msg) < (17 + len(hostname)):
			return False

		flags = struct.unpack(">H",msg[2:4])[0]

		# if the message is not query
		#if ((flags >> 15) & 0x1):
		#	return False

		questions = struct.unpack(">H",msg[4:6])[0]

		# if the message does not have any questions
		if questions != 1:
			return False

		(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[12:])

		if hostname != question_hostname[len(question_hostname)-len(hostname):]:
			return False

		return True

	def build_answer(self, transaction_id, record, orig_question):
		if record == None:
			flag = 0x8503 # 1000 0100 0000 0011
			answer_num = 0
			answers = ""
			additional_record_num = 0
			additional_records = ""
		else:
			flag = 0x8500 #	1000 0100 0000 0000
			RRtype = self.reverse_RR_type(record[0])
			if RRtype[1] == None:
				answer_num = 0
				answers = ""
				additional_record_num = 0
				additional_records = ""
			else:
				answer_num = 1
				(answer_num, answers, additional_record_num, additional_records) = RRtype[1](record)

		dns_header = struct.pack(">HHHHHH", transaction_id, flag, 1, answer_num, 0, additional_record_num)

		return dns_header + orig_question + answers + additional_records

	def build_query(self, transaction_id, data, hostname, RRtype):
		flag = 0x0100 #0000 0010 0000 0000
		additional_num = self.edns
		dns_header = struct.pack(">HHHHHH", transaction_id, flag, 1, 0, 0, additional_num)
		additional_records = ""
		if self.edns:
			additional_records = self.build_record_OPT()
		qhostname = self.hostname_to_hostnamebin(data+hostname)

		return dns_header + qhostname + struct.pack(">HH", RRtype, 1) + additional_records

	def parse_questions(self, msg, nq):
		ret = {"length": -1}
		i = 0
		for q in xrange(nq):
			ret[q] = {}
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if hlen == 0:
				ret = {length: -1}
				return ret
			ret[q]["name"] = question_hostname
			i += hlen
			ret[q]["type"] = struct.unpack(">H",msg[i:i+2])[0]
			i += 2
			ret[q]["class"] = struct.unpack(">H",msg[i:i+2])[0]
			i += 2

		ret["length"] = i

		return ret

	def parse_answers(self, msg, nq):
		ret = {"length": -1}
		i = 0
		for q in xrange(nq):
			ret[q] = {}
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if hlen == 0:
				ret = {"length": -1}
				return ret
			ret[q]["name"] = question_hostname
			i += hlen
			ret[q]["type"] = struct.unpack(">H",msg[i:i+2])[0]
			i += 2
			ret[q]["class"] = struct.unpack(">H",msg[i:i+2])[0]
			i += 2
			ret[q]["ttl"] = struct.unpack(">I",msg[i:i+4])[0]
			i += 4
			ret[q]["datalen"] = struct.unpack(">H",msg[i:i+2])[0]
			i += 2
			ret[q]["data"] = msg[i:i+ret[q]["datalen"]]
			i += ret[q]["datalen"]

		ret["length"] = i
		return ret

	def parse_dns(self, msg, hostname):
		rdata = ""
		transaction_id = struct.unpack(">H",msg[0:2])[0]
		flags = struct.unpack(">H",msg[2:4])[0]
		nquestions = struct.unpack(">H",msg[4:6])[0]
		nanswers = struct.unpack(">H",msg[6:8])[0]
		nauthority = struct.unpack(">H",msg[8:10])[0]
		nadditional = struct.unpack(">H",msg[10:12])[0]

		i = 12

		if ((flags & 0xF) > 0) and ((flags & 0xF) != 3):
			# Format error/Server failure/Not Implemented/Refused
			return (None, None, None, None, None, None, None, None)
		
		questions = self.parse_questions(msg[i:], nquestions)
		orig_question = msg[i:i+questions["length"]]
		i += questions["length"]
		answers = self.parse_answers(msg[i:], nanswers)
		i += answers["length"]

		return (transaction_id, not ((flags >> 15) & 0x01), questions[0]["type"], nquestions, questions, orig_question, nanswers, answers)

		'''
		# parse question
		for q in xrange(questions):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if hlen == 0:
				return (None, None, None, None, None, None, None, 6)

			if question_hostname == hostname:
				short_hostname = ""
			else:
				short_hostname = question_hostname[0:len(question_hostname)-len(hostname)-1]

			if len(msg) >= i+hlen+4:
				orig_question = msg[i:i+hlen+4]
				i += hlen

				qtype = struct.unpack(">H",msg[i:i+2])[0]
				i += 4
			else:
				return (None, None, None, None, None, None, None, 6)

		for q in xrange(answers):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					rdata = msg[i+2:i+2+rdlength]
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None, 6)
			else:
				return (None, None, None, None, None, None, None, 6)

		for q in xrange(authority+additional):
			(hlen, question_hostname) = self.hostnamebin_to_hostname(msg[i:])
			if len(msg) >= i+hlen+10:
				i += hlen + 8
				rdlength = struct.unpack(">H",msg[i:i+2])[0]
				if len(msg) >= i + 2 + rdlength:
					i += 2 + rdlength
				else:
					return (None, None, None, None, None, None, None, 6)
			else:
				return (None, None, None, None, None, None, None, 6)
		return (transaction_id, not ((flags >> 15) & 0x01), short_hostname, qtype, orig_question, rdata, i, 0, answers)
		'''