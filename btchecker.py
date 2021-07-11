#!/usr/bin/python

'''
Change Cores=# of how many cores do you want to use (Script tested on i7-4500U 8 Cores - 5 K/s per Core. 3,456,000 Private Keys gene
rated per day)

Take into account VM as well (i3 with 2 cores but 4VM -> 8 threads). More cores is just more demanding for OS scheduler
(worth playing around, even above number of CPU cores)

from https://github.com/Xefrok/BitBruteForce-Wallet

$ more bit.txt (bitcoin account address list)
address
1xxxxxxxxxxxxxxx
1xxxxxxxxxxxxxxx
..

according to the bit.txt file size, enough memory is required. 4mb bit.txt file loading = 25gb ram

'''

import time
import datetime as dt
import smtplib
import os
import multiprocessing
from multiprocessing import Pool
import binascii, hashlib, base58, ecdsa
import pandas as pd


def ripemd160(x):
    d = hashlib.new('ripemd160')
    d.update(x)
    return d

def check_key(dict, key):
    ret = False
    if key in dict.keys():
        ret = True

    return ret

r = 0
cores=1

#priv_str = "0000000000000000000000000000000000000000000000000000000000000001"
#privinp = int(priv_str, 16).to_bytes(32, byteorder='big')
#priv = ecdsa.SigningKey.from_string(privinp, curve=ecdsa.SECP256k1)
#print("Private key:", priv.to_string().hex())
#pub = priv.get_verifying_key().to_string()

#privinp = priv_int.to_bytes(32, byteorder='big')
#priv = ecdsa.SigningKey.from_string(privinp, curve=ecdsa.SECP256k1)
#pub = priv.get_verifying_key().to_string()
#print("Private key:", priv.to_string().hex())
#print(pub.hex())

def seek(r, df_handler):
	global num_threads
	LOG_EVERY_N = 10000
	start_time = dt.datetime.today().timestamp()
	i = 0
	print("Core " + str(r) +":  Searching Private Key..")

	filename = 'bit.txt'

	dict_from_csv = pd.read_csv(filename, dtype={'address': object}).set_index('address').T.to_dict()
	while True:
		i=i+1
		# generate private key , uncompressed WIF starts with "5"
#		priv_key = os.urandom(32)
		priv_key = i.to_bytes(32, byteorder='big')
		fullkey = '80' + binascii.hexlify(priv_key).decode()
		sha256a = hashlib.sha256(binascii.unhexlify(fullkey)).hexdigest()
		sha256b = hashlib.sha256(binascii.unhexlify(sha256a)).hexdigest()
		WIF = base58.b58encode(binascii.unhexlify(fullkey+sha256b[:8]))

		# get public key , uncompressed address starts with "1"
		sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
#		print('prv:' + sk.to_string().hex())
		vk = sk.get_verifying_key()
#		print('pub:' + vk.to_string().hex())
		publ_key = '04' + binascii.hexlify(vk.to_string()).decode()
		hash160 = ripemd160(hashlib.sha256(binascii.unhexlify(publ_key)).digest()).digest()
		publ_addr_a = b"\x00" + hash160
		checksum = hashlib.sha256(hashlib.sha256(publ_addr_a).digest()).digest()[:4]
		publ_addr_b = base58.b58encode(publ_addr_a + checksum)
		priv = WIF.decode()
		pub = publ_addr_b.decode()
		time_diff = dt.datetime.today().timestamp() - start_time
#		print ('Worker '+str(r)+':'+ str(i) + '.-  # '+pub + ' # -------- # '+ priv+' # ')
		if (i % LOG_EVERY_N) == 0:
			print('Core :'+str(r)+" K/s = "+ str(i / time_diff))
			print ('Worker '+str(r)+':'+ str(i) + '.-  # '+pub + ' # -------- # '+ priv+' # ' + ' #oprv:' + sk.to_string
().hex())
		#pub = pub + '\n'

		if check_key(dict_from_csv, pub):
			msg = "\nPublic: " + str(pub) + " ---- Private: " + str(priv) + "YEI"
			text = msg
			#UNCOMMENT IF 2FA from gmail is activated, or risk missing your winning ticket;)
			#server = smtplib.SMTP("smtp.gmail.com", 587)
			#server.ehlo()
			#server.starttls()
			#server.login("example@gmail.com", "password")
			#fromaddr = "example@gmail.com"
			#toaddr = "example@gmail.com"
			#server.sendmail(fromaddr, toaddr, text)
			print(text)
			with open('Wallets.txt','a') as f:
				f.write(priv)
				f.write('     ')
				f.write(pub)
				f.write('     orig_priv:')
				f.write(sk.to_string().hex())
				f.write('     orig_pub:')
				f.write(vk.to_string().hex())
				f.write('\n')
				f.close()
			print ('WINNER WINNER CHICKEN DINNER!!! ---- ' +dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), pub, priv)

contador=0
if __name__ == '__main__':
	jobs = []
	df_handler = pd.read_csv(open('bit.txt', 'r'))
	for r in range(cores):
		p = multiprocessing.Process(target=seek, args=(r,df_handler))
		jobs.append(p)
		p.start()

