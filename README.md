# Maximo / Oracle TCPS Notes
# Configuring and testing an ssl connection with an Oracle database

####  Run the oracle express database

`podman run -d --name oracle-db --replace -p 1521:1521  -p 2484:2484 -p 1532:1532 -e ORACLE_PWD=password container-registry.oracle.com/database/express`

# Configure the certificate authority and certificates.

#### Step 1: Create a Certificate Authority

To create a certificate authority, you can use the `openssl` command to generate a private key and a certificate signing request (CSR) for the CA.

```bash
openssl genrsa -out ca-private-key.pem 2048
openssl req -x509 -new -nodes -key ca-private-key.pem -subj "/C=US/ST=State/L=Locality/O=Organization/CN=localhost" -out ca-cert.pem -days 3650
```

This will create a private key for the CA (saved in `ca-private-key.pem`) and a self-signed certificate for the CA (saved in `ca-cert.pem`).

#### Step 2: Create a CSR for the Oracle Database

To create a CSR for the Oracle database, you can use the `openssl` command to generate a private key and a CSR.

```bash
openssl genrsa -out oracle-private-key.pem 2048
openssl req -new -newkey rsa:2048 -nodes -keyout oracle-private-key.pem -out oracle-csr.pem -subj "/CN=0.0.0.0"
```

This will create a private key for the Oracle database (saved in `oracle-private-key.pem`) and a CSR (saved in `oracle-csr.pem`).

#### Step 3: Sign the CSR and Issue a Certificate

To sign the CSR and issue a certificate, you can use the `openssl` command to use the CA private key to sign the CSR.

```bash
openssl x509 -req -in oracle-csr.pem -CA ca-cert.pem -CAkey ca-private-key.pem -CAcreateserial -out oracle-cert.pem -days 3650
```

This will create a certificate for the Oracle database (saved in `oracle-cert.pem`).

#### Step 4: Add the Certificate to the Oracle Wallet

Copy the certificates into the pod:

```
podman cp oracle-ssl/oracle-cert.pem oracle-db:cert.crt
podman cp oracle-ssl/server.key oracle-db:client.key
```

Exec into the pod to run the tls configuration.

```
podman exec -it oracle-db /bin/bash
export TCPS_CERTS_LOCATION=/home/oracle
/opt/oracle/configTcps.sh 1532 0.0.0.0 pass_word
```

# Optional: Manuallly add the certificates.
The following command is only for reference as to how to interact with the oracle wallet.

To add the certificate to the Oracle wallet, you can use the `orapki` command to import the certificate.

```bash
orapki wallet create -wallet wallet
orapki wallet add -wallet oracle-wallet -trusted_cert -cert oracle-cert.pem
```

This will add the certificate to the Oracle wallet.

#### Step 5: Add the CA Authority to the Java Trust Store of the client.

To add the CA authority to the Java trust store, you can use the `keytool` command to import the CA certificate.

You can use the default truststore of the java runtime.
```
keytool -importcert -v -trustcacerts -alias myauthority -file ca-cert.pem -cacerts $JAVA_HOME/lib/security/cacerts -storepass changeit\n
```

Or a custom trust store.
```
keytool -importcert -alias oracle-ca -file ca-cert.pem -keystore java-truststore.jks -storepass changeit
```

This will add the CA certificate to the Java trust store.

### Test

openssl s_client -connect 0.0.0.0:1532 -CAfile ca/server_cert.pem

We can now see in the output that the server is presenting a certificate. That certificate is signed by a trusted ca with respect to us, the client.
We can see a succesfully established SSL session.
```
CONNECTED(00000003)
Can't use SSL_get_servername
depth=1 C = US, ST = State, L = Locality, O = Organization, CN = localhost
verify return:1
depth=0 CN = 0.0.0.0
verify return:1
---
Certificate chain
 0 s:CN = 0.0.0.0
   i:C = US, ST = State, L = Locality, O = Organization, CN = localhost
---
Server certificate

-----BEGIN CERTIFICATE-----
MIIC9DCCAdwCFFIj0zwc3kWP23kdU3Xu8sGESzaSMA0GCSqGSIb3DQEBCwUAMFsx
CzAJBgNVBAYTAlVTMQ4wDAYDVQQIDAVTdGF0ZTERMA8GA1UEBwwITG9jYWxpdHkx
FTATBgNVBAoMDE9yZ2FuaXphdGlvbjESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTI0
MDkyMDE1MTMzNFoXDTM0MDkxODE1MTMzNFowEjEQMA4GA1UEAwwHMC4wLjAuMDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ3++Gd/fubc1aHvcjer2+/Z
+9aJ/luA1Utg4n6HC92kh9jcC1DOTx2QLIU1ZRswsRIrrHqsTT7MWGL81WcBczx7
8ql97gL3tPwFxZgelXwu7nm/C4zy6tZJb08gkzRMQ6sqvXr4WrQCZDJxbqXXibwX
m/CEzOY4rAODowbuEXx1EusKf5NUu9p9yh0zJP5w8jZJLLipie7EQrBppPBhGyX0
4VD1N92QO9p4auJsx6H6H60Mak+KbbZU4r+01HZuUya2ooJg/5RGiLCm+NShcfYh
Yxqd5jKStE1X78AGcigyw5BqQcmKKP2cjqH8wbUlGRWv0MEjMgzcl36IuYAvUycC
AwEAATANBgkqhkiG9w0BAQsFAAOCAQEAfT0mwOMEylD3rYTznrYnobjYZjSPtMol
WSr8nf2NKrGJzSO0ziCPPyao2ea9ryvja7CHg+EnBDbnEO7N01jAPNPsaEU6O2Ry
vfWE+xeC7owshhVR+OKcy9vtJALR3R6sx0UiuYWX8CtsABwfv5S7ZUey5PGpNxV/
nwvKVU5TH7EpmxvEjYtHPKj32t/efEsr+IGakUmJzsgZvIVDiCnOKYZsk/1tx8Xi
e2DNsnLmTgpxqzeDWwfB9WbIRCv5hVgh3PxX+41D+2ktr+4MNw8VGYF6lWE9f+qK
S27mRUdy2N69l/TqhK9MtUJVzT1rrJOy6mp/uEpDaZPI8ezjSawACg==
-----END CERTIFICATE-----
subject=CN = 0.0.0.0

issuer=C = US, ST = State, L = Locality, O = Organization, CN = localhost

---
No client certificate CA names sent
Peer signing digest: SHA384
Peer signature type: RSA
Server Temp Key: ECDH, P-256, 256 bits
---
SSL handshake has read 1259 bytes and written 415 bytes
Verification: OK
---
New, TLSv1.2, Cipher is ECDHE-RSA-AES256-GCM-SHA384
Server public key is 2048 bit
Secure Renegotiation IS supported
Compression: NONE
Expansion: NONE
No ALPN negotiated
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES256-GCM-SHA384
    Session-ID: 85984CE01C015B7BCE54A5E27592358FAD096934067DD7DDB482534F3DD089EE
    Session-ID-ctx: 
    Master-Key: F1D08FF9E32D830D17A6909D10953577921D0F15C46280E8A88B294C9FB3076930CA5E28199DE5EE939CE162D66C62E8
    PSK identity: None
    PSK identity hint: None
    SRP username: None
    Start Time: 1727018204
    Timeout   : 7200 (sec)
    Verify return code: 0 (ok)
    Extended master secret: no

```
### Turn SSL_CLIENT_AUTHENTICATION=TRUE

If we turn the parameter `SSL_CLIENT_AUTHENTICATION=TRUE` we will see the following error:

In the oracle trace
```
    
TNS-00542: SSL Handshake failed
    Oracle error 1: 28860
ORA-28860: Fatal SSL error
    nt secondary err code: 29024
    nt OS err code: 0
opiodr aborting process unknown ospid (4002) as a result of ORA-609
2024-09-20T15:41:56.282807+00:00
Errors in file /opt/oracle/diag/rdbms/xe/XE/trace/XE_ora_4002.trc:
ORA-00609: could not attach to incoming connection
ORA-28860: Fatal SSL error

```


In the Java trace:



```
"CertificateRequest": {
  "certificate types": [ecdsa_sign, rsa_sign, dss_sign]
  "supported signature algorithms": [ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512, dsa_sha256, ecdsa_sha224, rsa_sha224, dsa_sha224, ecdsa_sha1, rsa_pkcs1_sha1, dsa_sha1]
  "certificate authorities": []
}
)
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.265 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.265 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp256r1_sha256
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.265 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.265 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp384r1_sha384
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.265 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.265 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp521r1_sha512
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.265 CEST|X509Authentication.java:246|No X.509 cert selected for RSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.266 CEST|CertificateRequest.java:809|Unavailable authentication scheme: rsa_pkcs1_sha256
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.266 CEST|X509Authentication.java:246|No X.509 cert selected for RSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.266 CEST|CertificateRequest.java:809|Unavailable authentication scheme: rsa_pkcs1_sha384
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.266 CEST|X509Authentication.java:246|No X.509 cert selected for RSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.266 CEST|CertificateRequest.java:809|Unavailable authentication scheme: rsa_pkcs1_sha512
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.266 CEST|X509Authentication.java:246|No X.509 cert selected for DSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.266 CEST|CertificateRequest.java:809|Unavailable authentication scheme: dsa_sha256
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.266 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.266 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_sha224
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.267 CEST|X509Authentication.java:246|No X.509 cert selected for RSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:809|Unavailable authentication scheme: rsa_sha224
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.267 CEST|X509Authentication.java:246|No X.509 cert selected for DSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:809|Unavailable authentication scheme: dsa_sha224
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.267 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_sha1
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.267 CEST|X509Authentication.java:246|No X.509 cert selected for RSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:809|Unavailable authentication scheme: rsa_pkcs1_sha1
javax.net.ssl|ALL|01|main|2024-09-20 17:41:56.267 CEST|X509Authentication.java:246|No X.509 cert selected for DSA
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:809|Unavailable authentication scheme: dsa_sha1
javax.net.ssl|WARNING|01|main|2024-09-20 17:41:56.267 CEST|CertificateRequest.java:819|No available authentication scheme
javax.net.ssl|DEBUG|01|main|2024-09-20 17:41:56.268 CEST|ServerHelloDone.java:151|Consuming ServerHelloDone handshake message (
<empty>
)
javax.net.ssl|DEBUG|01|main|2024-09-20 17:41:56.268 CEST|CertificateMessage.java:299|No X.509 certificate for client authentication, use empty Certificate message instead
javax.net.ssl|DEBUG|01|main|2024-09-20 17:41:56.268 CEST|CertificateMessage.java:330|Produced client Certificate handshake message (
"Certificates": <empty list>
)
javax.net.ss
```

This is because the oracle server is now requesting a signed certificate from the client. This is called mutual TLS. 

We need to now configure our client to present a certificate which is signed by our CA. Then we need to configure the server to trust the CA
that signed our clients certificate. Note that even though the server presents a certificate signed by the CA, it does not have the CA itself in its truststore, meaning somewhat paradoxically 
that it will not trust other certificates that are signed by the same authority. This makes sense since that server has no way of knowing what CA signed its own certificate. Nevertheless, it is somewhat non-intuitive.

## Loading the certificate into the java keystore

keytool -importcert -v -trustcacerts -alias myauthority -file ca-cert.pem -cacerts $JAVA_HOME/lib/security/cacerts -storepass changeit\n


# Creating a keystore 

keytool -genkeypair -alias mykey -keyalg RSA -keysize 2048 -keystore mykeystore.jks -validity 365

# Client authentication 

We first need to create a certificate and key for our client.

```
openssl req -newkey rsa:2048 -keyout client-key.pem -out client-csr.pem -nodes -subj "/CN=Client"
```

Then we can create a CSR for the certificate.
```
openssl req -new -key client-key.pem -out client-csr.pem

```

We sign the certificate using the CA's private key.
```
openssl x509 -req -in client-csr.pem -CA ../ca/ca-cert.pem -CAkey ../ca/ca-private-key.pem -CAcreateserial -out client-cert.pem -days 365
```

We then need to import the certificate into the truststore of our java runtime.

```
openssl pkcs12 -export -in client.crt -inkey client.key -out client.p12 -name client-cert

keytool -importkeystore -deststorepass changeit -destkeypass changeit -destkeystore $JAVA_HOME/lib/security/cacerts -srckeystore client/client.p12 -srcstoretype PKCS12  -srcstorepass password -alias client-cert 
```

We can then try to run out application:


`/home/pat/.sdkman/candidates/java/11.0.23-sem/bin/java -Djavax.net.debug=all -Djavax.net.ssl.keyStore=java/mykeystore.jks -Djavax.net.ssl.keyStorePassword=password -javaagent:/home/pat/.local/share/idea-ce/lib/idea_rt.jar=38277:/home/pat/.local/share/idea-ce/bin -Dfile.encoding=UTF-8 -classpath /home/pat/Projects/clients/blm/oracle-ssl/target/classes:/home/pat/.m2/repository/com/oracle/database/jdbc/ojdbc8/19.8.0.0/ojdbc8-19.8.0.0.jar org.ibm.OracleConnection`

After doing this you should have a new error: unknown ca. This is because we have not added the CA that we used to sign the client certificate to the truststore of the Oracle database.

Copy the root certificate into the pod
`podman cp ca/ca-cert.pem oracle-db:ca-cert.pem`

Then import it into the wallet.

`orapki wallet add -wallet /opt/oracle/oradata/dbconfig/XE/.tls-wallet   -trusted_cert -cert ca-cert.pem`



After this is done, you can run again and you will see mutual authentication.

We can verify the logs:


```
javax.net.ssl|ALL|01|main|2024-09-23 10:36:44.466 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-23 10:36:44.466 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp256r1_sha256
javax.net.ssl|ALL|01|main|2024-09-23 10:36:44.466 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-23 10:36:44.466 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp384r1_sha384
javax.net.ssl|ALL|01|main|2024-09-23 10:36:44.466 CEST|X509Authentication.java:246|No X.509 cert selected for EC
javax.net.ssl|WARNING|01|main|2024-09-23 10:36:44.466 CEST|CertificateRequest.java:809|Unavailable authentication scheme: ecdsa_secp521r1_sha512
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.467 CEST|SunX509KeyManagerImpl.java:401|matching alias: client-cert
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.467 CEST|ServerHelloDone.java:151|Consuming ServerHelloDone handshake message (
<empty>
)
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.467 CEST|CertificateMessage.java:330|Produced client Certificate handshake message (
"Certificates": [
  "certificate" : {
    "version"            : "v1",
    "serial number"      : "52 23 D3 3C 1C DE 45 8F DB 79 1D 53 75 EE F2 C1 84 4B 36 96",
    "signature algorithm": "SHA256withRSA",
    "issuer"             : "CN=localhost, O=Organization, L=Locality, ST=State, C=US",
    "not before"         : "2024-09-23 09:15:51.000 CEST",
    "not  after"         : "2025-09-23 09:15:51.000 CEST",
    "subject"            : "EMAILADDRESS=patrick.harned@ibm.com, CN=localhost, OU=IBM, O=IBM, L=New York, ST=New York, C=US",
    "subject public key" : "RSA"}
]
)
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.467 CEST|ECDHClientKeyExchange.java:410|Produced ECDHE ClientKeyExchange handshake message (
"ECDH ClientKeyExchange": {
  "ecdh public": {
    0000: 04 AE D1 EF 56 20 46 09   1E ED 64 56 83 54 52 9F  ....V F...dV.TR.
    0010: AD 7D 7C 15 E4 93 5B 51   67 A1 59 BE 1E D9 FE F4  ......[Qg.Y.....
    0020: 1D C0 10 E5 F1 38 12 8E   5D C7 FD AF 13 BD 2D AD  .....8..].....-.
    0030: 1C 58 FD A7 0F B6 D8 FE   46 45 ED E3 43 57 6B 61  .X......FE..CWka
    0040: F2                                                 .
  },
}
)
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.470 CEST|CertificateVerify.java:764|Produced CertificateVerify handshake message (
"CertificateVerify": {
  "signature algorithm": rsa_pkcs1_sha256



```

Followed by

```
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.597 CEST|SSLEngineInputRecord.java:214|READ: TLSv1.2 application_data, length = 134
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.598 CEST|SSLCipher.java:1671|Plaintext after DECRYPTION (
  0000: 00 00 00 6E 06 00 00 00   00 00 08 01 56 4F 72 61  ...n........VOra
  0010: 63 6C 65 20 44 61 74 61   62 61 73 65 20 32 31 63  cle Database 21c
  0020: 20 45 78 70 72 65 73 73   20 45 64 69 74 69 6F 6E   Express Edition
  0030: 20 52 65 6C 65 61 73 65   20 32 31 2E 30 2E 30 2E   Release 21.0.0.
  0040: 30 2E 30 20 2D 20 50 72   6F 64 75 63 74 69 6F 6E  0.0 - Production
  0050: 0A 56 65 72 73 69 6F 6E   20 32 31 2E 33 2E 30 2E  .Version 21.3.0.
  0060: 30 2E 30 04 15 03 00 00   09 01 01 02 05 8F        0.0...........
)
Connected to the database successfully!
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.599 CEST|SSLEngineOutputRecord.java:280|WRITE: TLSv1.2 application_data, length = 13
javax.net.ssl|DEBUG|01|main|2024-09-23 10:36:44.599 CEST|SSLCipher.java:1769|Plaintext before ENCRYPTION (
  0000: 00 00 00 0D 06 00 00 00   00 00 03 09 04           .............
)

```
The message “No client certificate CA names sent” typically appears during the SSL/TLS handshake process. It means that the server did not send a list of acceptable Certificate Authority (CA) names to the client when requesting a client certificate. Here’s a bit more detail:
