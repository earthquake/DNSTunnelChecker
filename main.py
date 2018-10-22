# MIT License

# Copyright (c) 2018 Balazs Bucsay

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
import re
import os
import getopt
import random
import socket
import math

import dns_proto

class Tester():
	def __init__(self):
		self.DNS_proto = dns_proto.DNS_Proto()

		self.mode = 0
		self.nameserver = "8.8.8.8" # default google DNS server
		self.domain = ""
		self.short = "hsc"
		self.long = ["help", "server", "client", "nameserver=", "domain="]

		self.alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"

	def usage(self):
		print("[*] Usage: python main.py [options]:\nOptions:\n-h\t--help\t\tusage of the tool (this help)\n-s\t--server\tserver mode (default)\n-c\t--client\tclient mode\n\t--nameserver\tspecify nameserver (IPv4 address)\n\t--domain\tspecify domain")

	def run(self, argv):
		sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
		try:
			opts, args = getopt.getopt(argv, self.short, self.long)
		except getopt.GetoptError as e:
			self.usage()
			sys.exit(-1)

		for opt, arg in opts:
			if opt in ("-h", "--help"):
				self.usage()
				sys.exit(0)
			elif opt in ("-s", "--server"):
				self.mode = 0
			elif opt in ("-c", "--client"):
				self.mode = 1
			elif opt in ("--nameserver"):
				self.nameserver = arg
			elif opt in ("--domain"):
				self.domain = arg

		if not is_ipv4(self.nameserver):
			internal_print("Nameserver is not an IPv4 address, please correct", 1, -1)
			self.usage()
			sys.exit(-1)

		if not is_hostname(self.domain):
			internal_print("Domain is not a proper domain name, please correct", 1, -1)
			self.usage()
			sys.exit(-1)
			
		self.domain += "."

		try:
			if not self.mode:
				self.serve()
			else:
				self.connect()
		except KeyboardInterrupt:
			internal_print("Exiting")

	def serve(self):
		print("[*] Server mode started")

		server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_tuple = ("0.0.0.0", 53)
		server_socket.bind(server_tuple)

		while True:
			raw_message, addr = server_socket.recvfrom(4096)
			if not self.DNS_proto.is_valid_dns(raw_message, self.domain):
				internal_print("Some garbage was received, not DNS query", 1, -1)
				continue
			(transaction_id_received, queryornot, qtype, nquestions, questions, orig_question, nanswers, answers) = self.DNS_proto.parse_dns(raw_message, self.domain)
			if not queryornot:
				internal_print("DNS answer instead of query, strange!?", 1, -1)
				continue

			if nquestions:
				if len(questions[0]["name"])>5:
					try:
						num = int(questions[0]["name"][0:3])
						length = int(questions[0]["name"][3:6])
					except ValueError:
						continue
					record_type = questions[0]["name"][6:].split(".")[0].upper()
					qtype = self.DNS_proto.reverse_RR_type_num(record_type)
					if qtype in self.DNS_proto.RR_types:
						if not self.DNS_proto.RR_types[qtype][1]:
							internal_print("Record type not implemented yet.", 1, -1)
							continue
					else:
						internal_print("Invalid record type requested.", 1, -1)
						continue

					RRtype = self.DNS_proto.RR_types[qtype]
					encoded_text = []
					for i in xrange(num):
						 pre_text = "".join([random.choice(self.alphabet) for i in xrange(length)])
						 encoded_text.append(RRtype[2](pre_text))
					packet = self.DNS_proto.build_answer(transaction_id_received, [record_type, "", encoded_text, num, self.domain], orig_question)
					server_socket.sendto(packet, addr)


	def connect(self):
		internal_print("Client mode started")
		internal_print("Using {0} as DNS server".format(self.nameserver))

		server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		server_socket.settimeout(2.0)
		server_tuple = (self.nameserver, 53)

		# record A test
		record_type = "A"
		if not self.query(True, server_socket, server_tuple, record_type, record_type, 1, 4, 15, 0):
			internal_print("Basic test failed. Either you network is lossy or the DNS server does not work.", 1, -1)
			sys.exit(-1)

		
		#rate limit test 1
		print("")
		num = 30
		success = 0
		internal_print("Testing for rate limitation with record type {0}/{1} packets: ".format(record_type, num), 0)
		for i in xrange(num):
			if self.query(False, server_socket, server_tuple, record_type, record_type, 1, 4, 15, 0):
				success += 1
				internal_dot_print(True)
			else:
				internal_dot_print(False)
		print("")
		# hard coded 90%, made up number
		if (success/num)>0.90:
			internal_print("{0}% packet loss".format(100-(success/num*100)), 1, 1)
		else:
			internal_print("{0}% packet loss, lossy network or rate limit in place".format(100-(success/num*100)), 1, -1)
			internal_print("The following results might be incorrect", 1, -1)

		# record A test with CNAME response
		internal_print("Testing A record type with CNAME answer: ", 0, 0)
		if self.query(False, server_socket, server_tuple, "A", "CNAME", 1, 4, 15, 0):
			internal_print("Supported!", 1, 1)
		else:
			internal_print("Basic test failed. Either you network is lossy or the DNS does not work properly.", 1, -1)
			sys.exit(-1)

		# record CNAME test
		record_type = "CNAME"
		if not self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0):
			internal_print("CNAME record did not work. Exiting.", 1, -1)
			sys.exit(-1)
		

		#rate limit test 2
		print("")
		num = 50
		success = 0
		internal_print("Testing for rate limitation with record type {0}/{1} packets: ".format(record_type, num), 0)
		for i in xrange(num):
			if self.query(False, server_socket, server_tuple, record_type, record_type, 1, 4, 15, 0):
				success += 1
				internal_dot_print(True)
			else:
				internal_dot_print(False)
		print("")
		# hard coded 90%, made up number
		if (success/num)>0.90:
			internal_print("{0}% packet loss. Tunnelling could work.".format(100-(success/num*100)), 1, 1)
		else:
			internal_print("{0}% packet loss, lossy network or rate limit in place".format(100-(success/num*100)), 1, -1)
			internal_print("The following results might be incorrect", 1, -1)


		# EDNS test
		self.DNS_proto.set_edns(1)
		record_type = "CNAME"
		internal_print("Testing for EDNS support: ", 0, 0)
		if self.query(False, server_socket, server_tuple, record_type, record_type, 10, 100, 15, 512):
			internal_print("Supported!", 1, 1)
		else:
			internal_print("NOT supported!", 1, -1)
		self.DNS_proto.set_edns(0)


		# long domain name
		internal_print("Testing for long domain names in request: ", 0, 0)
		if self.query(False, server_socket, server_tuple, record_type, record_type, 1, 10, 100, 0):
			internal_print("Supported!", 1, 1)
		else:
			internal_print("Long domain names are not allowed. Exiting.", 1, -1)
			sys.exit(-1)


		# long domain name + long answer
		internal_print("Testing for big answer sizes: ", 0, 0)
		for i in xrange(10):
			internal_print("+{0}bytes: ".format(25*(i+1)), 0, 0)
			if self.query(False, server_socket, server_tuple, record_type, record_type, i+1, 25, 100, 0):
				internal_print("Supported!", 1, 1)
			else:
				internal_print("Too big", 1, -1)

		# AAAA with multiple answers
		record_type = "AAAA"
		internal_print("Testing for IPv6 AAAA tunnelling: ", 1, 0)
		for i in xrange(10):
			internal_print("{0} answers: ".format((i+1)), 0, 0)
			if self.query(False, server_socket, server_tuple, record_type, record_type, i+1, 16, 100, 0):
				internal_print("Supported!", 1, 1)
			else:
				internal_print("Too big", 1, -1)

		record_type = "TXT"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "PRIVATE"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "NULL"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "MX"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "SRV"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "DNSKEY"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 10, 15, 0)
		record_type = "RRSIG"
		self.query(True, server_socket, server_tuple, record_type, record_type, 1, 128, 15, 512)

	def query(self, verbose, server_socket, server_tuple, record_type1, record_type2, num, length, domain_length, edns):
		random_suffix = ""
		random_string = "".join( [random.choice(self.alphabet) for j in xrange(domain_length)] )
		for j in range(0,int(math.ceil(float(len(random_string))/63.0))):
			random_suffix += random_string[j*63:(j+1)*63]+"."
		record_hostname = format(num, "03d")+format(length, "03d")+record_type2.lower()+"."+random_suffix
		transaction_id = int(random.random() * 65535)

		if verbose:
			internal_print("Testing {0} record type with {1} answer(s): ".format(record_type2, num), 0)
		RRtype_num_r = self.DNS_proto.reverse_RR_type_num(record_type1)
		RRtype_num_a = self.DNS_proto.reverse_RR_type_num(record_type2)
		query = self.DNS_proto.build_query(transaction_id, record_hostname, self.domain, RRtype_num_r)
		server_socket.sendto(query, server_tuple)

		try:
			while True:
				raw_message, addr = server_socket.recvfrom(4096)
				if not self.DNS_proto.is_valid_dns(raw_message, self.domain):
					if verbose:
						internal_print("Some garbage was received, not DNS answers", 1, -1)
					continue
				(transaction_id_received, queryornot, qtype, nquestions, questions, orig_question, nanswers, answers) = self.DNS_proto.parse_dns(raw_message, self.domain)
				if transaction_id == transaction_id_received:
					break
				else:
					if verbose:
						internal_print("Wrong transaction_id received, ignoring.", 1, -1)
					continue

			if nanswers and ((RRtype_num_r == qtype)):
				if not 0 in answers:
					return False
				if (answers[0]["type"] == RRtype_num_a):
					if nanswers == num:
						if verbose:
							internal_print("Worked with {0} answer(s).".format(nanswers), 1, 1)
							if edns:
								if answers["length"] > edns:
									return True
								else:
									return False
					else:
						if verbose:
							internal_print("Only got back {0} answer(s).".format(nanswers), 1, -1)
						return False
				else:
					if verbose:
						internal_print("Unexpected record type {0}.".format(self.DNS_proto.RR_types[answers[0]["type"]][0]), 1, -1)
					return False
			else:
				if verbose:
					internal_print("Failed", 1, -1)
				return False

		except socket.timeout:
			if verbose:
				internal_print("No answer.", 1, -1)			
			return False

		return True

def internal_dot_print(feedback):
	colour = 1
	if feedback == True:
		if colour:
			text = "\033[92m"
		text += "."
	if feedback == False:
		if colour:
			text = "\033[91m"
		text += "!"
	sys.stdout.write(text)
		

def internal_print(message, newline = 1, feedback = 0, verbosity = 0, severity = 0):
	debug = ""
	colour = 1
	prefix = ""
	if severity == 2:
		debug = "DEBUG: "
	if verbosity >= severity:
		if feedback == -1:
			if colour:
				prefix = "\033[91m"
			prefix += "[-]"
		if feedback == 0:
			if colour:
				prefix = "\033[39m"
			prefix += "[*]"
		if feedback == 1:
			if colour:
				prefix = "\033[92m"
			prefix += "[+]"
		if colour:
			sys.stdout.write("{0} {1}{2}\033[39m".format(prefix, debug, message))
		else:
			sys.stdout.write("{0} {1}{2}".format(prefix, debug, message))
		if newline:
			sys.stdout.write("\n")

def is_hostname(s):
	return bool(re.match("^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$", s))

def is_ipv4(s):
	return bool(re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", s))

# main function
if __name__ == "__main__":
		print("DNS Tunnel Checker v0.1 by Balazs Bucsay [@xoreipeip]")
		tester = Tester()
		tester.run(sys.argv[1:])