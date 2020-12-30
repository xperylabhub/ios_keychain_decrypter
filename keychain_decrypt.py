################################################################################################
#                                                                                              #
# iOS Keychain Decrypter                                                                       #
# inspired by https://github.com/n0fate/iChainbreaker                                          #
# and https://github.com/nabla-c0d3/iphone-dataprotection.keychainviewer/tree/master/Keychain  #
#                                                                                              #
# Copyright Matthieu Regnery 2020                                                              #
#                                                                                              #
# This program is free software: you can redistribute it and/or modify                         #
# it under the terms of the GNU General Public License as published by                         #
# the Free Software Foundation, either version 3 of the License, or                            #
# (at your option) any later version.                                                          #
#                                                                                              #
# This program is distributed in the hope that it will be useful,                              #
# but WITHOUT ANY WARRANTY; without even the implied warranty of                               #
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                                #
# GNU General Public License for more details.                                                 #
#                                                                                              #
# You should have received a copy of the GNU General Public License                            #
# along with this program.  If not, see <https://www.gnu.org/licenses/>.                       #
################################################################################################


import sqlite3
import pandas
from struct import unpack
import SecDbKeychainSerializedItemV7_pb2
import SecDbKeychainSerializedSecretData_pb2
import SecDbKeychainSerializedMetadata_pb2
import SecDbKeychainSerializedAKSWrappedKey_pb2
import subprocess
import sys
import os
from binascii import hexlify, unhexlify
import ccl_bplist
from io import BytesIO
from Crypto.Cipher import AES
from pyasn1.codec.der.decoder import decode
from base64 import b64encode
import plistlib
import time

# path to connect to keychain db
# can be found in /private/var/Keychains/keychain-2.db
KEYCHAIN_DEFAULT_PAHT = "keychain-2.db"


# itemv7 is encoded with protobuf.
# definition taken from Apple Open Source (Security/keychain/securityd)
# https://opensource.apple.com/source/Security/Security-59306.80.4/keychain/securityd/
def deserialize_data(rowitem):
	version = unpack('<L', rowitem['data'][0:4])[0]
	if version == 7:
		root = SecDbKeychainSerializedItemV7_pb2.SecDbKeychainSerializedItemV7()
		item = root.FromString(rowitem['data'][4:])
		rowitem['keyclass'] = item.keyclass
		encryptedSecretData_root = SecDbKeychainSerializedSecretData_pb2.SecDbKeychainSerializedSecretData()
		encryptedSecretData = encryptedSecretData_root.FromString(item.encryptedSecretData)
		SecDbKeychainSerializedAKSWrappedKey_root = SecDbKeychainSerializedAKSWrappedKey_pb2.SecDbKeychainSerializedAKSWrappedKey()
		encryptedSecretData_wrappedKey = SecDbKeychainSerializedAKSWrappedKey_root.FromString(encryptedSecretData.wrappedKey)
		rowitem['encryptedSecretData_wrappedKey'] = encryptedSecretData_wrappedKey.wrappedKey
		rowitem['encryptedSecretData_ciphertext'] = encryptedSecretData.ciphertext
		rowitem['encryptedSecretData_tamperCheck'] = encryptedSecretData.tamperCheck
		encryptedMetadata_root = SecDbKeychainSerializedMetadata_pb2.SecDbKeychainSerializedMetadata()
		encryptedMetadata = encryptedMetadata_root.FromString(item.encryptedMetadata)
		rowitem['encryptedMetadata_wrappedKey'] = encryptedMetadata.wrappedKey
		rowitem['encryptedMetadata_ciphertext'] = encryptedMetadata.ciphertext
		rowitem['encryptedMetadata_tamperCheck'] = encryptedMetadata.tamperCheck
	return rowitem


# unwrapping key has to take place on device
# use keyclass_unwrapper which has to be compiled and
# uploaded to device beforehand
# run iproxy 2222 44
# sshpass -p alpine scp -P2222 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no keyclass_unwrapper root@127.0.0.1:  
def unwrap_key(key, keyclass):
	if keyclass >=6 :
		ssh = subprocess.Popen([
				"sshpass",
				"-p",
				"alpine",
				"ssh",
				"-p2222", 
				"-o", 
				"UserKnownHostsFile=/dev/null", 
				"-o", 
				"StrictHostKeyChecking=no", 
				"root@127.0.0.1",
				"./keyclass_unwrapper",
				hexlify(key).decode("ascii"),
				str(int(keyclass))
			],
			shell=False,
			stdout=subprocess.PIPE,
			stderr=subprocess.PIPE)
		time.sleep(0.1)
		out = ssh.stdout.readlines()
		while out == 0:
			out = ssh.stdout.readlines()
			time.sleep(1)
		unwrapped_key = out[0]
	return unwrapped_key


# itemV7 has two main parts:
# 1. secretData containing password or key
# 2. metaData containing key/password name (ie acct)
# decrypt secretData by :
# - unwrapping key 
# - decrypting with AES GCM
# - parsing resulting ASN1 DER
def decrypt_secretData(item):
	if item['keyclass'] >=6 :
		unwrapped_key = unwrap_key(item['encryptedSecretData_wrappedKey'], item['keyclass'])
		bplist = BytesIO(item['encryptedSecretData_ciphertext'])
		plist = ccl_bplist.load(bplist)
		secretDataDeserialized = ccl_bplist.deserialise_NsKeyedArchiver(plist, parse_whole_structure=True)
		authCode = secretDataDeserialized['root']['SFAuthenticationCode']
		iv   = secretDataDeserialized['root']['SFInitializationVector']
		ciphertext = secretDataDeserialized['root']['SFCiphertext']

		gcm = AES.new(unhexlify(unwrapped_key)[:32], AES.MODE_GCM, iv)
		decrypted = gcm.decrypt_and_verify(ciphertext, authCode)

		der_data = decode(decrypted)[0]
		for k in der_data:
			if 'Octet' in str(type(k[1])):
				item['decrypted'].update({str(k[0]) : bytes(k[1])})
			else:
				item['decrypted'].update({str(k[0]) : str(k[1])})
	return item


# decrypt Metadata by :
# - unwrapping metadata key 
# - decrypting metadata key with AES GCM
# - decrypting metadata with AES GCM
# - parsing resulting ASN1 DER
def decrypt_Metadata(item, df_meta):
	if item['keyclass'] >=6 :
		bplist = BytesIO(item['encryptedMetadata_wrappedKey'])
		plist = ccl_bplist.load(bplist)
		metaDataWrappedKeyDeserialized = ccl_bplist.deserialise_NsKeyedArchiver(plist, parse_whole_structure=True)
		authCode = metaDataWrappedKeyDeserialized['root']['SFAuthenticationCode']
		iv   = metaDataWrappedKeyDeserialized['root']['SFInitializationVector']
		ciphertext = metaDataWrappedKeyDeserialized['root']['SFCiphertext']
		unwrapped_metadata_key = unwrap_key(
			df_meta[df_meta.keyclass == int(item['keyclass'])].iloc[0].data, 
			item['keyclass']
			)
		gcm = AES.new(unhexlify(unwrapped_metadata_key)[:32], AES.MODE_GCM, iv)
		metadata_key = gcm.decrypt_and_verify(ciphertext, authCode)

		bplist = BytesIO(item['encryptedMetadata_ciphertext'])
		plist = ccl_bplist.load(bplist)
		metaDataDeserialized = ccl_bplist.deserialise_NsKeyedArchiver(plist, parse_whole_structure=True)
		authCode = metaDataDeserialized['root']['SFAuthenticationCode']
		iv   = metaDataDeserialized['root']['SFInitializationVector']
		ciphertext = metaDataDeserialized['root']['SFCiphertext']

		gcm = AES.new(metadata_key[:32], AES.MODE_GCM, iv)
		decrypted = gcm.decrypt_and_verify(ciphertext, authCode)
		der_data = decode(decrypted)[0]
		item['decrypted'] = {}
		for k in der_data:
			if 'Octet' in str(type(k[1])):
				item['decrypted'][str(k[0])] = bytes(k[1])
			else:
				item['decrypted'][str(k[0])] = str(k[1])


	return item

def main():
	keychain_path = KEYCHAIN_DEFAULT_PAHT

	if len(sys.argv) > 1:
		keychain_path = sys.argv[1]

	if not os.path.exists(keychain_path):
		raise IOError("Can not find keychain database in {}".format(keychain_path))

	db = sqlite3.connect(keychain_path)

	# extract data from generic password table
	df_genp = pandas.read_sql_query(
	"""
	SELECT * FROM genp;
	""", db)

	# extract data from internet password table
	df_inet = pandas.read_sql_query(
	"""
	SELECT * FROM inet;
	""", db)


	# extract metadata class keys to decrypt metadata
	df_meta = pandas.read_sql_query(
	"""
	SELECT * FROM metadatakeys;
	""", db)
	df_meta['keyclass'] = df_meta['keyclass'].astype(int)


	# decrypt
	df_genp = df_genp.apply(lambda r: deserialize_data(r), axis=1)
	df_genp = df_genp.apply(lambda r: decrypt_Metadata(r, df_meta), axis=1)
	df_genp = df_genp.apply(lambda r: decrypt_secretData(r), axis=1)

	df_inet = df_inet.apply(lambda r: deserialize_data(r), axis=1)
	df_inet = df_inet.apply(lambda r: decrypt_Metadata(r, df_meta), axis=1)
	df_inet = df_inet.apply(lambda r: decrypt_secretData(r), axis=1)

	res_dict = {
		'genp': df_genp['decrypted'].to_list(),
		'inet': df_inet['decrypted'].to_list()
	}
	

	# Exporting result

	with open("keychain_decrypted.plist","wb") as out:
		plistlib.dump(res_dict, out, sort_keys=False )

if __name__ == "__main__":
    main()


	    