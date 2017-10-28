#!/usr/bin/env python


"""
ARP spoofing detector

This script builds a trusted IP to ARP mapping and watches ARP packets to detect spoofing attempts.
"""

from scapy.all import *
import termcolor
import os
import re
import logging
from argparse import ArgumentParser


TRUSTED_ARP_TABLE = {}


def add_host(host_ip, host_mac):
    """ Adds a host IP and MAC to the watch table """
    print termcolor.colored('[*] Discovered new host: {} ({})'.format(host_mac, host_ip), 'green')
    logging.info('Discovered new host: {} ({})'.format(host_mac, host_ip))
    TRUSTED_ARP_TABLE[host_ip] = host_mac


def arp_callback(pkt):
    """ Inspects ARP packets and detects ARP spoofing attempts """
    # Add host to the list if unknown
    if pkt.hwsrc != '00:00:00:00:00:00' and not pkt.psrc in TRUSTED_ARP_TABLE:
        add_host(pkt.psrc, pkt.hwsrc)
    if pkt.hwdst != '00:00:00:00:00:00' and not pkt.pdst in TRUSTED_ARP_TABLE:
        add_host(pkt.pdst, pkt.hwdst)
    
    # Detect ARP spoofing
    if TRUSTED_ARP_TABLE[pkt.psrc] != pkt.hwsrc:
        log_string = 'ARP spoofing attempt from {} ({})'.format(
            pkt.hwsrc, 
            TRUSTED_ARP_TABLE[pkt.psrc] if pkt.src in TRUSTED_ARP_TABLE else '???')
        print termcolor.colored('[!] ' + log_string, 'red')
        logging.critical(log_string)


def load_OS_arp_table():
    print "Loading OS ARP table..."
    logging.info(termcolor.colored("Loading OS ARP table..."))
    output = os.popen('arp -an').read()
    parsed_output = re.findall(
        '\(([0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3})\) at ([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})', output)
    for i in parsed_output:
        add_host(i[0], i[1])
    logging.info("Finished loading OS ARP table.")
    print "Finished loading OS ARP table."


if __name__ == '__main__':
    parser = ArgumentParser()
    parser.add_argument('-o', '--logfile', help='Output log file')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    datefmt='%d/%m/%Y %H:%M:%S',
                    filename=args.logfile if args.logfile else '/dev/null',
                    filemode='a')

    logging.info("Starting ARP spoofing detector")
    load_OS_arp_table()   
    pkts = sniff(filter="arp", store=0, prn=arp_callback)
