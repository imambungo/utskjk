# UTS Keamanan Jaringan Komputer

M Imam Pratama  
09021281722063  
IF Reg A 17

## Aturan

- Beberapa soal sebagian merupakan soal capture the flag atau ctf (bisa dibaca
  di
https://dev.to/molly_struve/learn-how-to-hack-capture-the-flag-for-beginners-744).
- Setiap soal akan diberikan hints/clue agar bisa menjawab, dan beberapa task,
  sudah disediakan tools untuk memecahkan masalah.
- Dalam memecahkan permasalahan/soal, kita harus menggunakan tools yang
  berhubungan dengan soal tersebut, misalkan soal dengan file .pcap akan dapat
  dibuka dengan wireshark atau tcpdump.
- Untuk format penjelasan jawaban terhadap soal disebut dengan write-up, setiap
  soal akan di jawab dengan write-up nya, beserta referensi website dimana anda
  mendapatkan tata cara dalam memecahkan masalah tersebut.

## Soal

#### Hash functions

1. account.txt (10 points)  
   hints: hash functions, brute force.  
   note: untuk soal Hash function, adalah men-decode password yang tersedia
	  pada soal.

#### HTTP webfiles/pcap files

1. task_1_http_viewers.pcapng (10 points)  
   hints: http stream.
2. task_2_http_headers.pcapng (10 points)  
   hints: http stream headers.
3. task_3_website_login.pcapng (20 points)  
   hints: javascript, js obfuscator, weblogin, hash function algorithms.

#### TLS/SSL

1. tls/ssl_part1 -> task_ssl.pcap (20 points)  
   hints: tlsv1, ssl, rsa
2. tls/ssl_part2 -> e_corp_pki.pcapng (30points)  
   hints: tlsv1, ssl, modulus, exponent, rsa.

## Flag/Jawaban

#### Hash functions

1. `angelica`, `kaitlynn4`, `iluveddie1` (10 points) 

#### HTTP webfiles/pcap files

1. `HTTP_viewers_is_easY` (10 points)
2. `This_is_HTTP_headers_` (10 points)
3. `JavaScript Encryption` (20 points)

#### TLS/SSL

1. `MoreInterestingCryptoChallengesAhead!` (20 points)
2. `when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves` (30 points)

## Write-ups

### Hash Functions

Identifikasi tipe hash dari setiap hash menggunakan [hash-identifier](https://github.com/blackploit/hash-identifier):

![](img/hash-id.png)

Gunakan website [md5decrypt.net](https://md5decrypt.net/) untuk mendecrypt hash
sesuai tipe hash:

- Password 1:
    ![](img/solusi1_1.png)
- Password 2:
    ![](img/solusi1_2.png)
- Password 3:
    ![](img/solusi1_3.png)

### HTTP webfiles/pcap files

#### Task 1

1. Buka file task_1_http_viewers.pcapng menggunakan wireshark

2. Follow HTTP Stream dari baris yang berisi info "(text/html)"
	![](img/http1.png)

3. Lihat hasilnya
	![](img/http1_2.png)

#### Task 2

##### Cara 1

Lihat header di Packet Details Panel

![](img/http2cara1.png)

##### Cara 2

Sama seperti [Task 1](#task-1).

![](img/http2cara2.png)

#### Task 3

### TLS/SSL

#### Task 1

Flag: `MoreInterestingCryptoChallengesAhead!`

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

	Dapat di lihat, untuk public-key menggunakan RSA, dengan modulus 768 dan untuk
	faktorisasi 768 sendiri, RSA-768=3347807169895689878604416984821269081770479498371376856891243138898288379878002287614711652531743087737814467999489
	×
	36746043666799590428244633799627952632279158164343087642676032283815739666511279233373417143396810270092798736308917  
	Dengan nilai exponent: 65537  
	Sebagai kesimpulan, kita dapat membuat private cetificate kita sendiri.

4. Membuat *private certificate*.
Untuk membuat private certificate nya kita dapat menggunakan RsaCtfTool
(https://github.com/Ganapati/RsaCtfTool) dan lakukan seperti berikut:

	```console
	imampt@galatulis:~/UTS/tlsssl_part1$ rsa --private -n 768 -e 65537 -p \
	33478071698956898786044169848212690817704794983713768568912431388982883793878002287\
	614711652531743087737814467999489 -q 36746043666799590428244633799627952632279158164343087642676032283815739666511279233\
	373417143396810270092798736308917 > private.key 
	imampt@galatulis:~/UTS/tlsssl_part1$ cat private.key
	-----BEGIN RSA PRIVATE KEY-----
	MIIBywIBAAJhAMrZhFV8l+A5Qxoiatcn8MbUPvPUGEafGzdQSbIphD7p+Dsfl3OK
	wnT19h9AHyHxkT5LZLsxtVo405jA3+0AsTkvCIlxHESzWeeXbGF/zHNPBuPpXCZH
	YJG1L0YueUE9tQIDAQABAmB0DeSHYEQoNbqtXhmQRTqdFtt5dtP4u5i/mcDAHL6b
	nBK4CMgGg9HjRsFseawWKHTyjKYQwbl+Xh/66VclzgxrAxw+GIsXGHp5OzIsxABM
	Vo52ybJYVC6iotbs1GL/9AECMQDZgux7RA4oadJTXlH5G6zD6266BC4Qbm+HXD0X
	5T22X//W5OmjYITOYPg9dU3X9wECMQDuvm3SPOfpnA4iSf7MRBjDSvdOQYv6cUw3
	kYKEFKsY8y/X4JMGKkmwMCJcyEX5mrUCMQCXWi353DJJ1tDe6Bv8TlCah+GlmLEB
	CAedVgbA8OhPVl+tBd65q7jd7sXt5glDxQECMQCnEe/8Xc7U9fYWHL4H5+eEUuO5
	ibkRK1Pw1w0ErQoGzbe/VFLOz6z9dNG3KBd/0rkCMH6J+q8/eK2Vi+vGXc92zSHp
	lI4rshqBvhCfrDcrtBuu7b38Z1dz+ky1xc4ZO17bnA==
	-----END RSA PRIVATE KEY-----
	```

5. Men-*decrypt https*

Setelah mendapatkan private-key, gunakan key tersebut menggunakan wireshark.
Edit -> Preferences -> RSA key -> Add new keyfile, pilih private.key yang sudah
digenerate tadi. Reload file packet data tersebut dan follow TLS stream dari
baris yang berisikan info "OK (text/html)".

![](img/ssl_task_1.png)

#### Task 2

flag:`when_solving_problems_dig_at_the_roots_instead_of_just_hacking_at_the_leaves`

Lakukan langkah 1-3 dari Task 1:

```console
imampt@galatulis:~/UTS/tlsssl_part1$ openssl x509 -inform DER -in certificate.der -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            9e:6e:0d:aa:09:10:fa:fb
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C = US, ST = New York, L = New York, O = E Corp, CN = pki.e-corp.com, emailAddress = pki@e-corp.com
        Validity
            Not Before: Feb  1 00:39:00 2017 GMT
            Not After : Feb  1 00:39:00 2018 GMT
        Subject: C = US, ST = New York, L = New York, O = E Corp, CN = pki.e-corp.com, emailAddress = pki@e-corp.com
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (4103 bit)
                Modulus:
                    72:6f:6f:74:00:00:00:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:00:1b:00:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:77:77:77:7b:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
                    00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
                    00:00:00:00:00:1f:ff:ff:22:22:22:2b:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
                    26:52:93:c4:42:2b:e3:53:26:38:fe:eb:2a:63:5e:
                    86:5e:5b:cc:d4:86:2d:14:91:f8:e4:6e:d4:1a:fd:
                    ab:32:ab:1e:91:3c:29:6c:45:a7:23:a3:71:cc:4a:
                    d2:18:d2:73:a4:94:ac:50:1a:1c:67:75:76:b8:4d:
                    3a:17:00:b2:4e:38:f3:d7:c8:09:0c:95:27:67:f8:
                    a9:da:53:2e:b4:49:6a:95:3f:a2:b2:64:1f:93:af:
                    58:32:1e:49:1a:d6:b3:e1:f6:60:0e:a1:75:76:35:
                    a2:d4:75:62:df:f2:f2:45:bf:c8:ed:51:14:20:93:
                    1d:e2:46:d5:63:34:d8:89:7d:64:65:b2:27:f6:c0:
                    95:ec:e1:ad:99:4c:75:51:f0:8d:bc:21:f8:b4:06:
                    91:ee:51:f5:f7:2d:05:2d:93:52:06:2f:90:b0:e7:
                    c5:2c:2e:b1:81:96:c2:c9:85:10:1a:f4:ea:c6:74:
                    99:39:6c:62:41:ad:4f:24:39:ed:11:f8:7d:67:e7:
                    3a:23:9b:86:5c:45:d6:5a:61:cf:0f:56:08:2d:e8:
                    31:b9:7f:b2:8a:e8:22:2a:71:95:e0:ec:06:c0:82:
                    81:ff:c1:6e:71:06:e7:7e:68:b8:c4:51:04:24:be:
                    eb:55:82:fe:21:cc:34:5f:53:53:46:82:b7:5c:36:
                    8d:73:c9
                Exponent: 31337 (0x7a69)
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                4D:EC:FC:58:C3:9F:6B:A7:C9:0F:FC:0B:25:FD:46:F2:7C:AB:F8:44
            X509v3 Authority Key Identifier: 
                keyid:4D:EC:FC:58:C3:9F:6B:A7:C9:0F:FC:0B:25:FD:46:F2:7C:AB:F8:44

            X509v3 Basic Constraints: 
                CA:TRUE
    Signature Algorithm: sha256WithRSAEncryption
         0d:f1:f7:4f:e1:a7:7d:0c:92:d7:29:69:09:0e:5a:49:2b:25:
         b5:95:1c:32:f6:6e:04:52:5e:fc:82:d1:9e:6a:6a:60:23:42:
         62:8a:37:24:7b:ac:f1:e6:d9:8b:d9:b7:53:a8:d5:c6:a9:9a:
         e8:7d:28:a2:41:74:1e:c5:1f:08:8c:de:7a:f1:28:f1:a9:ba:
         bf:fb:11:29:2a:3d:4f:d1:5b:a2:5f:86:ba:e8:09:30:d3:c4:
         40:67:b2:57:bd:80:b2:c9:bf:98:d2:9e:ab:2c:07:65:9f:5e:
         3f:44:8c:5f:d9:b7:a0:aa:85:5c:9d:f1:46:90:0c:7f:41:35:
         24:73:99:49:03:5f:a3:a8:45:26:c0:51:ce:0b:a5:e0:30:2a:
         59:4e:98:77:fb:4a:83:3c:af:09:e8:61:47:a5:80:1f:b0:8c:
         f0:7e:9a:b5:75:54:bd:b0:8f:05:9e:04:75:d8:c0:e6:4b:b5:
         6b:ba:20:0c:14:fb:4c:87:c3:e9:8f:47:ba:1e:23:70:9d:5b:
         bd:11:63:a3:45:e2:91:54:02:b2:af:f6:ff:cb:c7:bd:0e:b1:
         87:bf:19:11:59:93:77:1c:a0:f5:b7:1a:c1:24:d6:1d:b2:70:
         0b:96:ac:34:45:80:8d:27:53:45:15:d9:75:89:02:45:60:aa:
         ee:0e:8f:0a:a0:36:e8:2a:00:18:09:d9:0a:2d:78:bb:06:f4:
         14:b4:04:2c:f6:c0:b6:5c:a3:f8:28:1b:91:b5:2b:9e:e4:af:
         35:cf:fb:b8:7b:ed:9f:73:7b:b6:14:a8:5e:21:5f:a0:66:76:
         3d:25:65:07:ff:02:ed:24:1f:07:d9:6a:79:db:c1:7f:ce:83:
         2c:bd:2f:1c:3a:22:41:a3:f3:30:27:b4:01:59:49:32:90:32:
         96:f0:a2:8b:b7:36:61:64:cf:7e:c1:97:bd:7b:25:e8:74:65:
         f4:d4:71:21:24:ba:10:95:c0:f7:9c:4d:c9:e8:82:1e:71:4d:
         d6:3b:9b:5c:f2:72:01:41:cc:34:f7:42:e2:e8:f5:a2:9c:21:
         61:08:5c:d4:b5:bf:fe:f4:ce:9f:b8:0e:fc:a8:9d:9f:8e:0f:
         a3:f6:41:98:73:77:cc:0b:d9:7b:5a:1f:54:fd:1f:75:bd:ba:
         d0:a1:de:ac:6f:43:a9:64:31:07:91:de:b4:0e:53:da:0d:08:
         07:dc:0a:f1:8a:03:30:6b:75:f5:96:43:b3:75:30:79:a9:8e:
         fd:06:5e:d1:c4:54:09:c7:f3:2f:69:a9:5a:8d:33:02:09:9d:
         4e:a3:63:33:66:ca:9a:82:f8:5f:5b:dc:3f:45:16:35:de:68:
         d2:17:bf:0b:15:b9:d9:ae:8b
-----BEGIN CERTIFICATE-----
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
-----END CERTIFICATE-----
```

Di dapat nilai modulus = 4103 dan exponent = 31337

untuk mendapatkan nilai p dan q, gunakan factorize2.py, didapat:  
p = 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232019973  
q = 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232018933

Buat private certificate:

```console
imampt@galatulis:~/UTS/tlsssl_part1$ rsa --private -n 4103 -e 31337 \
-p 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232019973 \
-q 345709341936068338730678003778405323582109317075021198605451259081268526297654818935837545259489748700537817158904946124698593212156185601832821337576558516676594811692389205842412600462658083813048872307642872332289082295535733483056820073388473845450507806559178316793666044371642249466611007764799781626418800031166072773475575269610775901034485376573476373962417949231752698909821646794161147858557311852386822684705642251949742285300552861190676326816587042282505137369676427345123087656274137257931639760324708350318503061363031086796994100943084772281097123781070811610760735943618425858558459014484742232018933 \
> private.key
imampt@galatulis:~/UTS/tlsssl_part1$ cat private.key
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
```

gunakan private.key tadi pada wireshark, reload wireshark, makan baris HTTP
akan terlihat. Saat kita follow SSL-nya, didapat:

![](img/ssl_task_2.png)

Hmm, kunci tersebut terlihat familiar. Jika kita sudah melihat source code
factorize2.py, maka kita tahu bahwa kita perlu memasukkan kunci di atas di
source code tersebut.

ganti potongan kode berikut di factorize2.py:

```python
n = """
726f6f740000000000000000000000
0000000000001b0000000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001fffff7777777b000000
00000000001ffffffffffffb000000
00000000001ffffffffffb00000000
00000000001ffffffffffb00000000
00000000001ffffffffffffb000000
00000000001fffff2222222b000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
00000000001ffffb00000000000000
265293c4422be3532638feeb2a635e
865e5bccd4862d1491f8e46ed41afd
ab32ab1e913c296c45a723a371cc4a
d218d273a494ac501a1c677576b84d
3a1700b24e38f3d7c8090c952767f8
a9da532eb4496a953fa2b2641f93af
58321e491ad6b3e1f6600ea1757635
a2d47562dff2f245bfc8ed51142093
1de246d56334d8897d6465b227f6c0
95ece1ad994c7551f08dbc21f8b406
91ee51f5f72d052d9352062f90b0e7
c52c2eb18196c2c985101af4eac674
99396c6241ad4f2439ed11f87d67e7
3a239b865c45d65a61cf0f56082de8
31b97fb28ae8222a7195e0ec06c082
81ffc16e7106e77e68b8c4510424be
eb5582fe21cc345f53534682b75c36
8d73c9""".replace('\n', '')
```

menjadi:

```python
n = """
72:6f:6f:74:00:00:00:00:00:00:00:00:00:00:00:
00:00:00:00:00:00:1b:00:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:ff:77:77:77:7b:00:00:00:
00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
00:00:00:00:00:1f:ff:ff:ff:ff:fb:00:00:00:00:
00:00:00:00:00:1f:ff:ff:ff:ff:ff:fb:00:00:00:
00:00:00:00:00:1f:ff:ff:22:22:22:2b:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:00:1f:ff:fb:00:00:00:00:00:00:00:
00:00:00:00:1f:ff:00:ff:fb:00:00:00:00:00:00:
00:00:00:00:1f:00:00:00:fb:00:00:00:00:00:00:
00:00:00:1f:00:00:00:00:00:fb:00:00:00:00:00:
00:00:00:1f:00:00:00:00:00:fb:00:00:00:00:00:
00:00:1f:00:00:00:00:00:00:00:fb:00:00:00:00:
00:00:1f:00:00:00:00:00:00:00:fb:00:00:00:00:
00:00:00:1f:00:00:00:00:00:fb:00:00:00:00:00:
00:00:00:1f:00:00:00:00:00:fb:00:00:00:00:00:
00:00:00:00:1f:00:00:00:fb:00:00:00:00:00:00:
00:00:00:00:1f:ff:00:ff:fb:00:00:00:00:00:00:
00:00:00:00:00:00:1b:00:00:00:00:00:00:00:00:
00:00:00:00:00:00:00:00:00:00:00:00:66:6c:61:
67:3a:77:68:65:6e:5f:73:6f:6c:76:69:6e:67:5f:
70:72:6f:62:6c:65:6d:73:5f:64:69:67:5f:61:74:
5f:74:68:65:5f:72:6f:6f:74:73:5f:69:6e:73:74:
65:61:64:5f:6f:66:5f:6a:75:73:74:5f:68:61:63:
6b:69:6e:67:5f:61:74:5f:74:68:65:5f:6c:65:61:
76:65:73""".replace('\n', '').replace(':', '')
```

Setelah itu gunakan factorize2.py untuk mendapatkan nilai p dan q yang asli

Ups, ternyata tidak berhasil, program berjalan terlalu lama.

### Kendala

fix rsa option not found:
https://osqa-ask.wireshark.org/questions/35600/not-able-to-configure-wireshark-with-gnutls/35616

fix rsa asking for password:
https://ask.wireshark.org/question/344/ive-imported-an-pem-key-but-why-wireshark-recognize-it-as-p12/

