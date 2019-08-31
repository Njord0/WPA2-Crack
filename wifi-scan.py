#coding: utf-8

"""
A simple wifi scanner using scapy to sniff beacon frame and probe response.
Author: Nicolas
github: https://github.com/nicolas031/
"""

import argparse
import ctypes
import subprocess
import logging
import time
import random
import sys
import os

from threading import Thread
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


parser = argparse.ArgumentParser()
parser.add_argument("-i","--interface", help="Network interface where packets will be sniffed", required=True)

args = parser.parse_args()

def main(interface):
	conf.iface = interface

	rand_channel_t = Thread(target=rand_channel, args=(interface,))
	rand_channel_t.start()

	print("Channel \t BSSID \t\t\t SSID")
	print("------- \t ----- \t\t\t ----")


	try:
		sniff(prn=packet_filter)
	except KeyboardInterrupt:
		sys.exit("[!] CTRL+C, exiting...")

def rand_channel(interface):
	while 1:
		rand_channel = random.randint(1, 14)

		subprocess.Popen("iwconfig {} channel {}".format(interface, int(rand_channel)), shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
		time.sleep(0.1)

def packet_filter(packet):
	if packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp):
		if not packet.addr3 in AP_LIST:
			AP_LIST.append(packet.addr3)
			ssid = packet[Dot11Elt].info if not b"\x00" in packet[Dot11Elt].info and packet[Dot11Elt].info != "" else "Unknow ssid"
			bssid = packet.addr3
			channel = int(ord(packet[Dot11Elt:3].info))

			print("{} \t\t {} \t {}".format(channel, bssid, ssid.decode()))


if __name__ == "__main__":
	AP_LIST = []
	DEV_LIST = []

	if sys.platform.startswith('linux'):
		if os.getuid() != 0:
			sys.exit("[!] This script need to run as root to work properly")


	elif sys.platform.startswith("win"):
		sys.exit("[!] This script is for linux only!")


	try:
		print("[+] Importing scapy...", end=" ")
		from scapy.all import *
		print("Done.")
	except ImportError:
		sys.exit("\n[!] Error happened while scapy module import")
	main(args.interface)
