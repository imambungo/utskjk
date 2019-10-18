fix rsa option not found:
https://osqa-ask.wireshark.org/questions/35600/not-able-to-configure-wireshark-with-gnutls/35616

fix rsa asking for password:
https://ask.wireshark.org/question/344/ive-imported-an-pem-key-but-why-wireshark-recognize-it-as-p12/

## Hash Functions

```console
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 9852d983162e307c438712f6cca37db2a69d69694df77c348477b33eaf5a7eff567921d2953b801c6a93f84e12ad0991bf5e1a58f96c305b8f1dc369d4d30e00

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
 HASH: 5efb876b5c9852ff621c1d0988511784935117295e4779de0080875578424bf72d554cf8a012baadd8f8a77c121844c5

Possible Hashs:
[+] SHA-384
[+] SHA-384(HMAC)
--------------------------------------------------
 HASH: cc401e187bfbadd2df7d1d66a2f1312b6a8ef4de80b1244165d94cf9b402cf28a4d73edeb2561178e6ba8720caaeaf4171559dfed4f5b19de746ff817e8f595d

Possible Hashs:
[+] SHA-512
[+] Whirlpool

Least Possible Hashs:
[+] SHA-512(HMAC)
[+] Whirlpool(HMAC)
--------------------------------------------------
 HASH:
```

```
angelica
```

## HTTP webfiles/pcap files

### Task 1

flag :`HTTP_viewers_is_easY`

1. Buka file task_1_http_viewers.pcapng menggunakan wireshark

2. Follow HTTP Stream dari baris yang berisi info "(text/html)"
	![](img/http1.png)

3. Lihat hasilnya
	![](img/http1_2.png)

### Task 2

Flag:`This_is_HTTP_headers_`

#### Cara 1

Lihat header di Packet Details Panel

![](img/http2cara1.png)

#### Cara 2

Sama seperti Task 1

![](img/http2cara2.png)

### Task 3

## TLS/SSL

### Task 1

1. Ekstraksi public certificate pada bari syang berisi info "Server Hello,
Certificate, Server Hello Done".
2. Lihat informasi pada Transport Layer Security > TLSv1 Record Layer :
Handshake Protocol: Certificate, klik kanan pada certificate dan pilih Export
Packet Bytes. Simpan dengan nama certificate.der
3. Identifikasi jenis teknik enkripsi apa yang digunakan:
	```console
	imampt@galatulis:~/UTS/tlsssl_part1$ openssl x509 -inform DER -in certificate.der -text
	Certificate:
	    Data:
	        Version: 3 (0x2)
	        Serial Number:
	            d7:08:17:fc:61:41:b3:1c
	        Signature Algorithm: sha1WithRSAEncryption
	        Issuer: C = KR, ST = Seoul, L = Seoul, O = CodeGate, OU = LM**2, CN = ctf1.codegate.org
	        Validity
	            Not Before: Mar 11 19:28:25 2010 GMT
	            Not After : Mar 11 19:28:25 2011 GMT
	        Subject: C = KR, ST = Seoul, L = Seoul, O = CodeGate, OU = LM**2, CN = ctf1.codegate.org
	        Subject Public Key Info:
	            Public Key Algorithm: rsaEncryption
	                RSA Public-Key: (768 bit)
	                Modulus:
	                    00:ca:d9:84:55:7c:97:e0:39:43:1a:22:6a:d7:27:
	                    f0:c6:d4:3e:f3:d4:18:46:9f:1b:37:50:49:b2:29:
	                    84:3e:e9:f8:3b:1f:97:73:8a:c2:74:f5:f6:1f:40:
	                    1f:21:f1:91:3e:4b:64:bb:31:b5:5a:38:d3:98:c0:
	                    df:ed:00:b1:39:2f:08:89:71:1c:44:b3:59:e7:97:
	                    6c:61:7f:cc:73:4f:06:e3:e9:5c:26:47:60:91:b5:
	                    2f:46:2e:79:41:3d:b5
	                Exponent: 65537 (0x10001)
	        X509v3 extensions:
	            X509v3 Subject Key Identifier: 
	                3E:35:CC:D2:D9:A5:5E:B7:E7:9C:03:E4:40:30:3A:9E:B3:BD:9D:F6
	            X509v3 Authority Key Identifier: 
	                keyid:3E:35:CC:D2:D9:A5:5E:B7:E7:9C:03:E4:40:30:3A:9E:B3:BD:9D:F6
	                DirName:/C=KR/ST=Seoul/L=Seoul/O=CodeGate/OU=LM**2/CN=ctf1.codegate.org
	                serial:D7:08:17:FC:61:41:B3:1C
	
	            X509v3 Basic Constraints: 
	                CA:TRUE
	    Signature Algorithm: sha1WithRSAEncryption
	         75:e9:15:ba:b2:b9:ec:d0:ef:ec:fd:27:44:a7:d9:0a:e6:ad:
	         84:57:8d:5f:3e:9b:97:0d:34:cb:d7:d4:2b:2e:9f:8d:d6:51:
	         a2:7c:cf:c1:5d:47:5a:83:1b:89:fd:f5:da:32:c9:73:00:2a:
	         58:8f:9a:bc:e7:fb:fe:69:0c:70:bd:a2:3f:01:4a:d1:95:8d:
	         4e:b4:6a:f1:83:dc:4d:97:e0:6f:e7:89:86:24:80:19:af:22:
	         b2:cd:7e:d0:8f:4e
	-----BEGIN CERTIFICATE-----
	MIIC4zCCAm2gAwIBAgIJANcIF/xhQbMcMA0GCSqGSIb3DQEBBQUAMGwxCzAJBgNV
	BAYTAktSMQ4wDAYDVQQIEwVTZW91bDEOMAwGA1UEBxMFU2VvdWwxETAPBgNVBAoT
	CENvZGVHYXRlMQ4wDAYDVQQLFAVMTSoqMjEaMBgGA1UEAxMRY3RmMS5jb2RlZ2F0
	ZS5vcmcwHhcNMTAwMzExMTkyODI1WhcNMTEwMzExMTkyODI1WjBsMQswCQYDVQQG
	EwJLUjEOMAwGA1UECBMFU2VvdWwxDjAMBgNVBAcTBVNlb3VsMREwDwYDVQQKEwhD
	b2RlR2F0ZTEOMAwGA1UECxQFTE0qKjIxGjAYBgNVBAMTEWN0ZjEuY29kZWdhdGUu
	b3JnMHwwDQYJKoZIhvcNAQEBBQADawAwaAJhAMrZhFV8l+A5Qxoiatcn8MbUPvPU
	GEafGzdQSbIphD7p+Dsfl3OKwnT19h9AHyHxkT5LZLsxtVo405jA3+0AsTkvCIlx
	HESzWeeXbGF/zHNPBuPpXCZHYJG1L0YueUE9tQIDAQABo4HRMIHOMB0GA1UdDgQW
	BBQ+NczS2aVet+ecA+RAMDqes72d9jCBngYDVR0jBIGWMIGTgBQ+NczS2aVet+ec
	A+RAMDqes72d9qFwpG4wbDELMAkGA1UEBhMCS1IxDjAMBgNVBAgTBVNlb3VsMQ4w
	DAYDVQQHEwVTZW91bDERMA8GA1UEChMIQ29kZUdhdGUxDjAMBgNVBAsUBUxNKioy
	MRowGAYDVQQDExFjdGYxLmNvZGVnYXRlLm9yZ4IJANcIF/xhQbMcMAwGA1UdEwQF
	MAMBAf8wDQYJKoZIhvcNAQEFBQADYQB16RW6srns0O/s/SdEp9kK5q2EV41fPpuX
	DTTL19QrLp+N1lGifM/BXUdagxuJ/fXaMslzACpYj5q85/v+aQxwvaI/AUrRlY1O
	tGrxg9xNl+Bv54mGJIAZryKyzX7Qj04=
	-----END CERTIFICATE-----
	```

