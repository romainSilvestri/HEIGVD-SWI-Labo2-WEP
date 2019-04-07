#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Romain Silvestri & Romain Gallay

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
import rc4


#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key 

# message à envoyer
msg = "123456789012345678901234567890123456"

# calculer l'icv en utilisant crc32
icv_enclair = crc32(msg)

# chiffrer le cleartext
cleartext = msg + struct.pack('<l', icv_enclair)
ciphertext = rc4.rc4crypt(cleartext, seed)

# mettre les données dans le packet
arp.wepdata = ciphertext[:-4]
arp.icv = struct.unpack('!L', ciphertext[-4:])[0]

# écrire le packet 
wrpcap('arp2.cap', arp)

