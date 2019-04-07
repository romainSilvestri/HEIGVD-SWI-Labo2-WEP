#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Romain Silvestri, Romain Gallay

""" Manually encrypt a wep message given the WEP key"""

from scapy.all import *
import binascii
import rc4
import sys

#Cle wep AA:AA:AA:AA:AA
key='\xaa\xaa\xaa\xaa\xaa'

#lecture de message chiffré - rdpcap retourne toujours un array, même si la capture contient un seul paquet
arp = rdpcap('arp.cap')[0]

# rc4 seed est composé de IV+clé
seed = arp.iv+key

# max size of data in 1 fragment
MAX_SIZE = 36

counter = 0
filename = "arp3.cap"

# message to send
base_msg = "Having tried in vain at every expence considerable trouble and some danger to unite the Suliotes for the good of Greece and their own I have come to the following resolution"

# delete the file if exists
try:
    os.remove(filename)
except OSError:
    pass


while (len(base_msg) > 0):

	# take the MAX_SIZE first characters of our message
	msg = base_msg[:MAX_SIZE]

	# pad the message WITH '0' if needed
	if (len(msg) < MAX_SIZE):
		msg += '0'*(MAX_SIZE - len(msg))

	# copy the arp request we are using
	fragment = arp

	# set the MF bit to 1 if needed
	if len(base_msg) <= MAX_SIZE:
		fragment.FCfield &= 0xfffb
	else:
		fragment.FCfield |= 0x004

	# increment the counter
	fragment.SC = counter

	# compute the icv
	icv_enclair = crc32(msg)

	# encrypt the cleartext with rc4
	cleartext = msg + struct.pack('<l', icv_enclair)
	ciphertext = rc4.rc4crypt(cleartext, seed)

	# copy the ciphertext in the fragment data
	fragment.wepdata = ciphertext[:-4]

	# set the fragment icv
	fragment.icv = struct.unpack('!L', ciphertext[-4:])[0]

	# write the fragment in the file
	wrpcap(filename, fragment, append=True)

	# modifiy msg and counter for the next iteration
	base_msg = base_msg[MAX_SIZE:]
	counter += 1


