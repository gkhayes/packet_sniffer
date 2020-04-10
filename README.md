# Packet Sniffer - README

## Installation
This code was written in Python 3 and requires the following packages: socket, numpy, sys, struct and re. 

*Note:* this code will only run in a Linux environment.

## Overview
This repository contains code for a Linux-based Python packet sniffer and analyser. When run, it will open a raw socket and will capture all network packets received through that socket. Once received, the program will parse the captured packets and return a layer by layer analysis of the information contained in each layer for the most popular internet protocols. Note that, for less common protocols, no information is returned.

Depending on the contents of the packets, the following information is returned by layer and protocol type:
* **Link layer**
  - *Ethernet frames:* Network layer protocol, source MAC address and destination MAC address;
* **Network layer**
  - *IPv4 datagrams:* Transport layer protocol, source IP address and destination IP address;
  - *ARP datagrams:* Sender MAC address, sender IP address, destination MAC address and destination IP address;
* **Transport layer**
  - *UDP segments:* Application layer protocol, source port and destination port;
  - *TCP segments:* Application layer protocol, sequence number, acknowledgement number, source port, destination port and flags;
* **Application layer**
  - *DNS messages:* Query ID, number of questions, number of answer resource records, number of authority resource records, number of additional resource records, details of any questions and details of any answer resource records;
  - *HTTP messages:* Header information.

## File Descriptions
* **sniffer.py:** Contains the main functionality for sniffing and analysing network packets. 
* **link.py:** Contains functions for parsing link layer frames (Ethernet frames).
* **network.py:** Contains functions for parsing network layer datagrams (IPv4 and ARP datagrams).
* **transport.py:** Contains functions for parsing transport layer segments (TCP and UDP segments).
* **application.py:** Contains functions for parsing application layer messages (DNS and HTTP messages).

## Running Instructions
1. Save the files contained in this repository to the current working directory.
2. From the current working directory, run the following command: `python sniffer.py <n>`,
  where `<n>` is replaced by an integer specifying the maximum number of packets to capture. 

If `<n>` is omitted, then the packet sniffer will continue to run until the process is interrupted via CTRL+C.

## Licencing, Authors, Acknowledgements
The code contained in this repository may be used freely with acknowledgement.
