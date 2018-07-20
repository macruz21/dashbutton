#!/usr/bin/env python
# -*- coding: utf-8 -*-
__author__ = 'macruz21'

from scapy.all import *

AMAZON_DEVICES = [
    'F0:D2:F1',
    '88:71:E5',
    'FC:A1:83',
    'F0:27:2D',
    '74:C2:46',
    '68:37:E9',
    '78:E1:03',
    '38:F7:3D',
    '50:DC:E7',
    'A0:02:DC',
    '0C:47:C9',
    '74:75:48',
    'AC:63:BE',
    'FC:A6:67',
    '18:74:2E',
    '00:FC:8B',
    'FC:65:DE',
    '6C:56:97',
    '44:65:0D',
    '50:F5:DA',
    '68:54:FD',
    '40:B4:CD',
    '00:71:47',
    '4C:EF:C0',
    '84:D6:D0',
    '34:D2:70',
    'B4:7C:9C',
    'F0:81:73',
]

def arp_monitor_callback(pkt):
    if pkt[ARP].op in (1, 2):  # who-has or is-at
        #print(pkt.sprintf("%ARP.hwsrc%"))
        #Ahora tenemos que ver si la mac obtenida, es alguna perteneciente a Amazon
        for device in AMAZON_DEVICES:
            if device.lower() in pkt.sprintf("%ARP.hwsrc%").lower():
                print('Amazon Dash Button encontrado:',pkt.sprintf("%ARP.hwsrc% %ARP.psrc%"))
                #return pkt.sprintf("%ARP.hwsrc% %ARP.psrc%")




sniff(prn=arp_monitor_callback, filter="arp", store=0)
