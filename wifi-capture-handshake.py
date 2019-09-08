#coding: utf-8

"""
Script to capture the eapol authentication when a client connect to the access point,
You shouldn't run wifi-scan.py at same time to avoid errors with the channel.
Author: Nicolas
github: https://github.com/nicolas031/
"""

import argparse
import binascii
import logging
import os
import subprocess
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", help="Network interface where packets will be sniffed", required=True)
parser.add_argument("-b", "--bssid", help="Access point BSSID", required=True)
parser.add_argument("-c", "--channel", help="Channel", required=True, type=int)

args = parser.parse_args()

PACKET_LIST = []
packet_1 = packet_2 = packet_3 = packet_4 = ""

def eapol_filter(packet):
	global PACKET_LIST
	global packet_1, packet_2, packet_3, packet_4
	if packet.haslayer(EAPOL):
		if args.bssid in [packet.addr1, packet.addr2, packet.addr3]:

			packet_raw = binascii.hexlify(packet[Raw].load)
			PACKET_LIST.append(packet)
			if packet_raw[2:6] == "008a".encode(): #message_1
				packet_1 = packet
				
			elif packet_raw[2:6] == "010a".encode(): #message_2
				packet_2 = packet

			elif packet_raw[2:6] == "13ca".encode(): #message_3
				packet_3 = packet

			elif packet_raw[2:6] == "030a".encode(): #message_4
				packet_4 = packet


			if len(PACKET_LIST) == 4:
				print("[+] 4-Way handshake captured, now saving...")

				PACKET_LIST = [packet_1, packet_2, packet_3, packet_4]
				try:
					wrpcap("wpa_handshake01.pcap", PACKET_LIST)

					sys.exit("[+] Done.")

				except Exception as e:
					print(e)

def main(interface, bssid, channel):
	conf.iface = interface

	subprocess.Popen("iwconfig {} channel {}".format(interface, channel), shell=True)

	print("[+] Capturing 4-Way handshake [{}]...".format(bssid))
	sniff(prn=eapol_filter)

if __name__ == "__main__":

	if sys.platform.startswith("linux"):
		if os.getuid() != 0:
			sys.exit("[!] This script need to run as root to work properly")
	elif sys.platform.startswith("win"):
		sys.exit("[!] This script is for linux only!")

	if not args.channel in range(1, 14):
		sys.exit("[!] Channel must be in range 1-14")

	try:
		print("[+] Importing scapy...", end="")
		from scapy.all import *
		print("Done.")
	except ImportError:
		sys.exit("\n[!] Error happened while importing scapy")
	main(args.interface, args.bssid, args.channel)