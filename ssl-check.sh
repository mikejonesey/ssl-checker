#!/bin/bash

if [ -n "$1" ]; then
	hostname=$1
else
	read -p "Enter the fqdn: " hostname
fi

if [ -n "$2" ]; then
	servername="$2"
else
	echo "assuming hostname is the servername"
	servername="$1"
fi

printf "\e[0;37m"

#pfs_ciphers="ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES256-GCM-SHA384:DHE-DSS-AES128-GCM-SHA256:DHE-DSS-AES256-SHA256:DHE-DSS-AES128-SHA256"

pfs_ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES256-CCM8:ECDHE-ECDSA-AES256-CCM:DHE-RSA-AES256-CCM8:DHE-RSA-AES256-CCM:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-CCM8:ECDHE-ECDSA-AES128-CCM:DHE-RSA-AES128-CCM8:DHE-RSA-AES128-CCM:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:ECDHE-ECDSA-CAMELLIA256-SHA384:ECDHE-RSA-CAMELLIA256-SHA384:DHE-RSA-CAMELLIA256-SHA256:DHE-DSS-CAMELLIA256-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ECDHE-ECDSA-CAMELLIA128-SHA256:ECDHE-RSA-CAMELLIA128-SHA256:DHE-RSA-CAMELLIA128-SHA256:DHE-DSS-CAMELLIA128-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-DSS-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:DHE-DSS-CAMELLIA256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:DHE-DSS-CAMELLIA128-SHA:DHE-PSK-AES256-GCM-SHA384:DHE-PSK-CHACHA20-POLY1305:ECDHE-PSK-CHACHA20-POLY1305:DHE-PSK-AES256-CCM8:DHE-PSK-AES256-CCM:DHE-PSK-AES128-GCM-SHA256:DHE-PSK-AES128-CCM8:DHE-PSK-AES128-CCM:ECDHE-PSK-AES256-CBC-SHA384:ECDHE-PSK-AES256-CBC-SHA:DHE-PSK-AES256-CBC-SHA384:DHE-PSK-AES256-CBC-SHA:ECDHE-PSK-CAMELLIA256-SHA384:DHE-PSK-CAMELLIA256-SHA384:ECDHE-PSK-AES128-CBC-SHA256:ECDHE-PSK-AES128-CBC-SHA:DHE-PSK-AES128-CBC-SHA256:DHE-PSK-AES128-CBC-SHA:ECDHE-PSK-CAMELLIA128-SHA256:DHE-PSK-CAMELLIA128-SHA256"

weak_ciphers="EDH-RSA-DES-CBC-SHA:EDH-DSS-DES-CBC-SHA:ADH-DES-CBC-SHA:DES-CBC-SHA:RC4:EXPORT"

function printText(){
	if [ "$1" == "inf" ]; then
		#info
		printf "\e[0;33m"
	elif [ "$1" == "atn" ]; then
		#attention
		printf "\e[1;33m"
	elif [ "$1" == "good" ]; then
		#good
		printf "\e[0;32m"
	elif [ "$1" == "val" ]; then
		#value
		printf "\e[0;36m"
	elif [ "$1" == "err" ]; then
		#error
		printf "\e[0;31m"
	else
		#norm white
		printf "\e[0;37m"
	fi
	while read aline; do echo "$aline"; done
	echo -ne "\e[0m"
}

function checkClient(){
	servername="$1"
	hostname="$2"
	clientname="$3"
	goodcipher_list="$4"
	badcipher_list="$5"
	client_test=$(openssl s_client -connect $hostname:443 -servername $servername -tls1 -cipher "$goodcipher_list:$badcipher_list" </dev/null 2>&1)
	protoUsed=$(echo "$client_test" | egrep "New, (SSLv3|TLSv1/SSLv3|TLSv1.1|TLSv1.2), Cipher is .*" | sed 's/, Cipher is .*//;s/New, //')
	cipherUsed=$(echo "$client_test" | egrep "New, (SSLv3|TLSv1/SSLv3|TLSv1.1|TLSv1.2), Cipher is .*" | sed 's/.*Cipher is //')
	if [ -z "$cipherUsed" ]; then
		echo -e "\e[0;31m  $clientname:  NO\e[0;37m"
	elif [[ $badcipher_list == *$cipherUsed* ]]; then
		echo -e "\e[0;31m  $clientname:  NO - only supports weak ciphers\e[0;37m"
	elif [[ $goodcipher_list == *$cipherUsed* ]]; then
		if [[ ":$pfs_ciphers:" != *:$cipherUsed:* ]]; then
			echo -e "\e[0;32m  $clientname:  YES : p: $protoUsed c: $cipherUsed (NO PFS)\e[0;37m"
		else
			echo -e "\e[0;32m  $clientname:  YES : p: $protoUsed c: $cipherUsed : PFS\e[0;37m"
		fi
	fi
}

function genericCipherTest(){
	servername="$1"
	hostname="$2"
	cipher_list="$3"
	client_test=$(openssl s_client -connect $hostname:443 -servername $servername -tls1 -cipher "$cipher_list" </dev/null 2>&1)
	cipherUsed=$(echo "$client_test" | egrep "New, (TLSv1/SSLv3|TLSv1.1|TLSv1.2), Cipher is .*" | sed 's/.*Cipher is //')
	if [ -z "$cipherUsed" ]; then
		return 1
	elif [[ $cipher_list == *$cipherUsed* ]]; then
		return 0
	fi
}

function checkPfsCipher(){
	hostname="$1"
	servername="$2"
	# Support for > 1024 bit keys
	#ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(256) Mac=AEAD
	#ECDHE-ECDSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(256) Mac=AEAD
	#ECDHE-RSA-AES256-SHA384 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA384
	#ECDHE-ECDSA-AES256-SHA384 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA384
	#DHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(256) Mac=AEAD
	#DHE-RSA-AES256-SHA256   TLSv1.2 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA256
	#ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
	#ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128) Mac=AEAD
	#ECDHE-RSA-AES128-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA256
	#ECDHE-ECDSA-AES128-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA256
	#DHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=DH       Au=RSA  Enc=AESGCM(128) Mac=AEAD
	#DHE-RSA-AES128-SHA256   TLSv1.2 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA256
	# Support for <= 1024 bit keys
	#DHE-DSS-AES256-GCM-SHA384 TLSv1.2 Kx=DH       Au=DSS  Enc=AESGCM(256) Mac=AEAD
	#DHE-DSS-AES256-SHA256   TLSv1.2 Kx=DH       Au=DSS  Enc=AES(256)  Mac=SHA256
	#DHE-DSS-AES128-GCM-SHA256 TLSv1.2 Kx=DH       Au=DSS  Enc=AESGCM(128) Mac=AEAD
	#DHE-DSS-AES128-SHA256   TLSv1.2 Kx=DH       Au=DSS  Enc=AES(128)  Mac=SHA256
	pfs_test=$(openssl s_client -connect $hostname:443 -servername $servername -cipher "$pfs_ciphers" </dev/null 2>&1)
	if [ -n "$(echo "$pfs_test" | grep "error setting cipher list")" ]; then
		echo "Local Testing node does not support pfs ciphers" >&2
		return 1
	elif [ -n "$(echo "$pfs_test" | grep "alert handshake failure")" ]; then
		echo "Server being tested does not support pfs ciphers" >&2
		return 1
	elif [ -n "$(echo "$pfs_test" | grep "SSL handshake has read")" -a -n "$(echo "$pfs_test" | egrep "New, (TLSv1/SSLv3|TLSv1.1|TLSv1.2), Cipher is .*DSS.*")" ]; then
		echo "Server being tested supports pfs but only using depriciated ciphers" >&2
		echo "1024 bit"
		return 2
	elif [ -n "$(echo "$pfs_test" | grep "SSL handshake has read")" ]; then
		cipherUsed=$(echo "$pfs_test" | egrep "New, (TLSv1/SSLv3|TLSv1.1|TLSv1.2), Cipher is .*" | sed 's/.*Cipher is //')
		echo "$cipherUsed"
		return 0
	fi
	return 3
}

function checkDomain(){
	servername="$1"
	hostname="$2"
	connection=$(openssl s_client -showcerts -connect $hostname:443 -servername $servername </dev/null 2>/dev/null)

	if [ -z "$connection" ]; then
		echo -e "\e[0;31m  Connection Failed!\e[0;37m"
		exit 1
	fi

	if [[ "$connection" == *CN=$hostname* ]]; then
		echo "Certificate valid for domain $servername"  | printText good
	elif [[ "$connection" == *CN=\*.$(echo "$hostname" | sed 's/[a-z\-]*\.//')* ]]; then
		echo "Wildcard certificate valid for domain $servername" | printText good
	elif [[ "$connection" == *CN=\*.$(echo "$servername" | sed 's/[a-z\-]*\.//')* ]]; then
		echo "Wildcard certificate valid for domain (Alias) $servername" | printText good
	else
		echo "Certificate is not valid for domain $servername" | printText err
	fi

	echo ""

	echo "$connection"|tr "\n" "~"|sed 's/END CERTIFICATE-----~/END CERTIFICATE-----\n/g'|grep "CERTIFICATE"| while read al; do 
		crt=$(echo "$al" | tr "~" "\n" | openssl x509 -noout -text)
		crt_cname=$(echo "$crt" | grep "Subject: .*CN=" | grep -o "CN=[a-zA-Z0-9. ]*" | sed 's/CN=//')

		echo "Certificate: $crt_cname"
		crt_alg=$(echo "$crt" | head -6 | grep "Signature Algorithm" | sed 's/.* //')
		if [ "$crt_alg" == "sha1WithRSAEncryption" ]; then
			echo -e "\e[0;31m  Signature Algorithm: $crt_alg\e[0;37m"
		else
			echo -e "\e[0;32m  Signature Algorithm: $crt_alg\e[0;37m"
		fi
		echo "  Validity:"
		crt_date=$(echo "$crt" | grep "Validity" -A 2)
		crt_date_nb=$(echo "$crt_date" | grep "Not Before")
		crt_date_nb=$(echo ${crt_date_nb:24:24})
		if [ "$(date -d "$crt_date_nb" +"%s")" -gt "$(date +"%s")" ]; then
			echo -e "\e[0;31m    Not Before: $crt_date_nb\e[0;37m"
		else
			echo -e "\e[0;32m    Not Before: $crt_date_nb\e[0;37m"
		fi

		crt_date_nb=$(echo "$crt_date" | grep "Not After")
		crt_date_nb=$(echo ${crt_date_nb:24:24})
		if [ "$(date -d "$crt_date_nb" +"%s")" -lt "$(date +"%s")" ]; then
			echo -e "\e[0;31m    Not After:  $crt_date_nb\e[0;37m"
		else
			echo -e "\e[0;32m    Not After:  $crt_date_nb\e[0;37m"
		fi
		echo
	done

	echo "Connection Details:"

	pub_key_bit=$(echo "$connection" | grep -o "Server public key is [0-9]* bit" | sed 's/Server public key is \([0-9]*\) bit/\1/')
	if [ "$pub_key_bit" -lt "2048" ]; then
		echo -e "\e[0;31m  Pub key bits: $pub_key_bit\e[0;37m"
	else
		echo -e "\e[0;32m  Pub key bits: $pub_key_bit\e[0;37m"
	fi

	sec_reneg=$(echo "$connection" | grep "Secure Renegotiation IS supported")
	if [ -z "$sec_reneg" ]; then
		echo -e "\e[0;31m  Secure Renegotiation: NO SUPPORT\e[0;37m"
	else
		echo -e "\e[0;32m  Secure Renegotiation: YES\e[0;37m"
	fi

	pfsCipher=$(checkPfsCipher "$hostname" "$servername")
	if [ "$pfsCipher" == "1024 bit" ]; then
		echo -e "\e[0;31m  Supports PFS:  NO - bit limit 1024\e[0;37m"
	elif [ -z "$pfsCipher" -o "$pub_key_bit" -lt "2048" ]; then
		echo -e "\e[0;31m  Supports PFS:  NO\e[0;37m"
	else
		echo -e "\e[0;32m  Supports PFS:  YES : $pfsCipher : $pub_key_bit\e[0;37m"
	fi
	echo ""

	echo "Weak cipher test:"
	genericCipherTest "$servername" "$hostname" "$weak_ciphers"
	if [ "$?" != "1" ]; then
		echo -e "\tWeak ciphers supported" | printText err
		weak_cipher_list=($(echo "$weak_ciphers" | sed 's/:/ /g'))
		for ((i=0; i<${#weak_cipher_list[@]}; i++)); do
			genericCipherTest "$servername" "$hostname" "${weak_cipher_list[$i]}"
			if [ "$?" != "1" ]; then
				echo "Weak cipher support: ${weak_cipher_list[$i]}" | printText err
			fi			
		done
	else
		echo -e "\tNo weak ciphers supported" | printText good
	fi
	echo ""

	echo "Client Support:" | printText

	##################################################
	# Android 2.3.7
	##################################################
	
	#WEAK#SSL_RSA_WITH_RC4_128_MD5 - RC4-MD5                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=MD5
	#WEAK#SSL_RSA_WITH_RC4_128_SHA - RC4-SHA                 SSLv3 Kx=RSA      Au=RSA  Enc=RC4(128)  Mac=SHA1
	#TLS_RSA_WITH_AES_128_CBC_SHA - AES128-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA1
	#TLS_DHE_RSA_WITH_AES_128_CBC_SHA - DHE-RSA-AES128-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA1
	#TLS_DHE_DSS_WITH_AES_128_CBC_SHA - DHE-DSS-AES128-SHA      SSLv3 Kx=DH       Au=DSS  Enc=AES(128)  Mac=SHA1
	#WEAK#SSL_RSA_WITH_3DES_EDE_CBC_SHA - DES-CBC3-SHA            SSLv3 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=SHA1
	#WEAK#SSL_DHE_RSA_WITH_3DES_EDE_CBC_SHA - DHE-RSA-DES-CBC3-SHA    SSLv3 Kx=DH       Au=RSA  Enc=3DES(168) Mac=SHA1
	#WEAK#SSL_DHE_DSS_WITH_3DES_EDE_CBC_SHA - DHE-DSS-DES-CBC3-SHA    SSLv3 Kx=DH       Au=DSS  Enc=3DES(168) Mac=SHA1
	#WEAK#SSL_RSA_WITH_DES_CBC_SHA - DES-CBC-SHA             SSLv3 Kx=RSA      Au=RSA  Enc=DES(56)   Mac=SHA1
	#WEAK#SSL_DHE_RSA_WITH_DES_CBC_SHA - DHE-RSA-DES-CBC-SHA     SSLv3 Kx=DH       Au=RSA  Enc=DES(56)   Mac=SHA1
	#WEAK#SSL_DHE_DSS_WITH_DES_CBC_SHA - DHE-DSS-DES-CBC-SHA     SSLv3 Kx=DH       Au=DSS  Enc=DES(56)   Mac=SHA1
	#WEAK#SSL_RSA_EXPORT_WITH_RC4_40_MD5 - EXP-RC4-MD5             SSLv3 Kx=RSA(512) Au=RSA  Enc=RC4(40)   Mac=MD5  export
	#WEAK#SSL_RSA_EXPORT_WITH_DES40_CBC_SHA - EXP-DES-CBC-SHA         SSLv3 Kx=RSA(512) Au=RSA  Enc=DES(40)   Mac=SHA1 export
	#WEAK#SSL_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA - EXP-DHE-RSA-DES-CBC-SHA SSLv3 Kx=DH(512)  Au=RSA  Enc=DES(40)   Mac=SHA1 export
	#WEAK#SSL_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA - EXP-DHE-DSS-DES-CBC-SHA SSLv3 Kx=DH(512)  Au=DSS  Enc=DES(40)   Mac=SHA1 export
	checkClient "$servername" "$hostname" "Android 2.3.7" "AES128-SHA:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA" "RC4-MD5:RC4-SHA:DES-CBC3-SHA:DHE-RSA-DES-CBC3-SHA:DHE-DSS-DES-CBC3-SHA:DES-CBC-SHA:DHE-RSA-DES-CBC-SHA:DHE-DSS-DES-CBC-SHA:EXP-RC4-MD5:EXP-DES-CBC-SHA:EXP-DHE-RSA-DES-CBC-SHA:EXP-DHE-DSS-DES-CBC-SHA"

	##################################################
	# Android 4.0.4
	##################################################

#	checkClient "$servername" "$hostname" "Android 4.0.4" "" ""

	##################################################
	# Android 4.1.1
	##################################################

#	checkClient "$servername" "$hostname" "Android 4.1.1" "" ""

	##################################################
	# Android 4.2.2
	##################################################

#	checkClient "$servername" "$hostname" "Android 4.2.2" "" ""

	##################################################
	# Android 4.3
	##################################################

#	checkClient "$servername" "$hostname" "Android 4.3" "" ""

	##################################################
	# Android 4.4.2
	##################################################

#	checkClient "$servername" "$hostname" "Android 4.4.2" "" ""

	##################################################
	# Android 5.0.0
	##################################################

#	checkClient "$servername" "$hostname" "Android 5.0.0" "" ""

	##################################################
	# Chrome 43 / OS X
	##################################################

#	checkClient "$servername" "$hostname" "Chrome 43 / OS X" "" ""

	##################################################
	# Firefox 31 Win 7
	##################################################

#	checkClient "$servername" "$hostname" "???" "" ""

	##################################################
	# Firefox 39 / OS X
	##################################################

#	checkClient "$servername" "$hostname" "???" "" ""

	##################################################
	# Firefox 40 / Linux
	##################################################
	#0xC0,0x2B - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 - ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128) Mac=AEAD
	#0xC0,0x2F - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
	#0xC0,0x0A - TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA - ECDHE-ECDSA-AES256-SHA  SSLv3 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA1
	#0xC0,0x09 - TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA - ECDHE-ECDSA-AES128-SHA  SSLv3 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA1
	#0xC0,0x13 - TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA - ECDHE-RSA-AES128-SHA    SSLv3 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA1
	#0xC0,0x14 - TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA - ECDHE-RSA-AES256-SHA    SSLv3 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
	#0x00,0x33 - TLS_DHE_RSA_WITH_AES_128_CBC_SHA - DHE-RSA-AES128-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA1
	#0x00,0x39 - TLS_DHE_RSA_WITH_AES_256_CBC_SHA - DHE-RSA-AES256-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA1
	#0x00,0x2F - TLS_RSA_WITH_AES_128_CBC_SHA - AES128-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA1
	#0x00,0x35 - TLS_RSA_WITH_AES_256_CBC_SHA - AES256-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA1
        #0x00,0x0A - SSL_RSA_WITH_3DES_EDE_CBC_SHA - DES-CBC3-SHA            SSLv3 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=SHA1

	checkClient "$servername" "$hostname" "Firefox 40 / Linux" "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:AES128-SHA:AES256-SHA:DES-CBC3-SHA" ""

        ##################################################
        # Firefox 45.5.1 / Linux
        ##################################################
        # 0xC0,0x2B - ECDHE-ECDSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=ECDSA Enc=AESGCM(128) Mac=AEAD
        # 0xC0,0x2F - ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 Kx=ECDH     Au=RSA  Enc=AESGCM(128) Mac=AEAD
        # 0xC0,0x0A - ECDHE-ECDSA-AES256-SHA  SSLv3 Kx=ECDH     Au=ECDSA Enc=AES(256)  Mac=SHA1
        # 0xC0,0x09 - ECDHE-ECDSA-AES128-SHA  SSLv3 Kx=ECDH     Au=ECDSA Enc=AES(128)  Mac=SHA1
        # 0xC0,0x13 - ECDHE-RSA-AES128-SHA    SSLv3 Kx=ECDH     Au=RSA  Enc=AES(128)  Mac=SHA1
        # 0xC0,0x14 - ECDHE-RSA-AES256-SHA    SSLv3 Kx=ECDH     Au=RSA  Enc=AES(256)  Mac=SHA1
        # 0x00,0x33 - DHE-RSA-AES128-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(128)  Mac=SHA1
        # 0x00,0x39 - DHE-RSA-AES256-SHA      SSLv3 Kx=DH       Au=RSA  Enc=AES(256)  Mac=SHA1
        # 0x00,0x2F - AES128-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(128)  Mac=SHA1
        # 0x00,0x35 - AES256-SHA              SSLv3 Kx=RSA      Au=RSA  Enc=AES(256)  Mac=SHA1
        # 0x00,0x0A - DES-CBC3-SHA            SSLv3 Kx=RSA      Au=RSA  Enc=3DES(168) Mac=SHA1

	checkClient "$servername" "$hostname" "Firefox 45.5.1 / Linux" "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA" "AES128-SHA:AES256-SHA:DES-CBC3-SHA"

	##################################################
	# Googlebot Feb 2015
	##################################################

#	checkClient "$servername" "$hostname" "Googlebot Feb 2015" "" ""

	##################################################
	# IE 6 / XP  
	##################################################

#	checkClient "$servername" "$hostname" "IE 6 / XP" "" ""

	##################################################
	# IE 7 / Vista
	##################################################

#	checkClient "$servername" "$hostname" "IE 7 / Vista" "" ""

	##################################################
	# IE 8 / XP 
	##################################################

#	checkClient "$servername" "$hostname" "IE 8 / XP " "" ""

	##################################################
	# IE 8-10 / Win 7
	##################################################

#	checkClient "$servername" "$hostname" "IE 8-10 / Win 7" "" ""


	##################################################
	# IE 11 / Win 7
	##################################################

#	checkClient "$servername" "$hostname" "IE 11 / Win 7" "" ""

	##################################################
	# IE 11 / Win 8.1 
	##################################################

#	checkClient "$servername" "$hostname" "IE 11 / Win 8.1" "" ""

	##################################################
	# IE 10 / Win Phone 8.0
	##################################################

#	checkClient "$servername" "$hostname" "IE 10 / Win Phone 8.0" "" ""

	##################################################
	# IE 11 / Win Phone 8.1
	##################################################

#	checkClient "$servername" "$hostname" "IE 11 / Win Phone 8.1" "" ""

	##################################################
	# IE 11 / Win Phone 8.1 Update
	##################################################

#	checkClient "$servername" "$hostname" "IE 11 / Win Phone 8.1 Update" "" ""

	##################################################
	# Edge 12 / Win 10 (Build 10130) 
	##################################################

#	checkClient "$servername" "$hostname" "Edge 12 / Win 10 (Build 10130) " "" ""

	##################################################
	# Java 6u45 
	##################################################

#	checkClient "$servername" "$hostname" "Java 6u45 " "" ""

	##################################################
	# Java 7u25
	##################################################

#	checkClient "$servername" "$hostname" "Java 7u25" "" ""

	##################################################
	# Java 8u31
	##################################################

#	checkClient "$servername" "$hostname" "Java 8u31" "" ""

	##################################################
	# OpenSSL 0.9.8y
	##################################################

#	checkClient "$servername" "$hostname" "OpenSSL 0.9.8y" "" ""

	##################################################
	# OpenSSL 1.0.1l 
	##################################################

#	checkClient "$servername" "$hostname" "OpenSSL 1.0.1l " "" ""

	##################################################
	# OpenSSL 1.0.2 
	##################################################

#	checkClient "$servername" "$hostname" "OpenSSL 1.0.2 " "" ""

	##################################################
	# Safari 5.1.9 / OS X 10.6.8
	##################################################

#	checkClient "$servername" "$hostname" "Safari 5.1.9 / OS X 10.6.8" "" ""

	##################################################
	# Safari 6 / iOS 6.0.1
	##################################################

#	checkClient "$servername" "$hostname" "Safari 6 / iOS 6.0.1" "" ""

	##################################################
	# Safari 6.0.4 / OS X 10.8.4
	##################################################

#	checkClient "$servername" "$hostname" "Safari 6.0.4 / OS X 10.8.4" "" ""

	##################################################
	# Safari 7 / iOS 7.1 
	##################################################

#	checkClient "$servername" "$hostname" "Safari 7 / iOS 7.1 " "" ""

	##################################################
	# Safari 7 / OS X 10.9
	##################################################

#	checkClient "$servername" "$hostname" "Safari 7 / OS X 10.9" "" ""

	##################################################
	# Safari 8 / iOS 8.4
	##################################################

#	checkClient "$servername" "$hostname" "Safari 8 / iOS 8.4" "" ""

	##################################################
	# Safari 8 / OS X 10.10
	##################################################

#	checkClient "$servername" "$hostname" "Safari 8 / OS X 10.10" "" ""

	##################################################
	# Yahoo Slurp Jan 2015
	##################################################

#	checkClient "$servername" "$hostname" "Yahoo Slurp Jan 2015" "" ""

#	checkClient "$servername" "$hostname" "Android 2.3.7" "" ""
#	checkClient "$servername" "$hostname" "Android 2.3.7" "" ""
#	checkClient "$servername" "$hostname" "Android 2.3.7" "" ""
#	checkClient "$servername" "$hostname" "Android 2.3.7" "" ""
#	checkClient "$servername" "$hostname" "Android 2.3.7" "" ""
	
}

checkDomain "$hostname" "$servername"

