# ssl-checker

Useful script when testing either a firwalled service, or a service with no DNS yet...

sample output:

    mike@mike-laptop4:~/git/linux-tools/ssl-checker$ ./ssl-check.sh twitter.com
    assuming hostname is the servername
    Certificate valid for domain twitter.com

    Certificate: twitter.com
      Signature Algorithm: sha256WithRSAEncryption
      Validity:
        Not Before: Jan 12 00:00:00 2017 GMT
        Not After:  Jan 17 12:00:00 2019 GMT

    Certificate: DigiCert SHA2 Extended Validation Server CA
      Signature Algorithm: sha256WithRSAEncryption
      Validity:
        Not Before: Oct 22 12:00:00 2013 GMT
        Not After:  Oct 22 12:00:00 2028 GMT

    Connection Details:
      Pub key bits: 2048
      Secure Renegotiation: YES
      Supports PFS:  YES : ECDHE-RSA-AES128-GCM-SHA256 : 2048

    Weak cipher test:
    Weak ciphers supported
    Weak cipher support: AES256-GCM-SHA384
    Weak cipher support: AES256-SHA256
    Weak cipher support: AES256-SHA
    Weak cipher support: ECDHE-RSA-DES-CBC3-SHA
    Weak cipher support: AES128-GCM-SHA256
    Weak cipher support: AES128-SHA256
    Weak cipher support: AES128-SHA
    Weak cipher support: DES-CBC3-SHA

    Client Support:
      Android 2.3.7:  YES : cp: TLSv1/SSLv3 sp: TLSv1.2 c: AES128-SHA (NO FS)
      Firefox 40 / Linux:  YES : cp: TLSv1/SSLv3 sp: TLSv1.2 c: ECDHE-RSA-AES128-GCM-SHA256 : FS
      Firefox 45.5.1 / Linux:  YES : cp: TLSv1/SSLv3 sp: TLSv1.2 c: ECDHE-RSA-AES128-GCM-SHA256 : FS

Note, of the "weak" ciphers supported only the DES ciphers are an issue for 
PCI compliance / has a current vulerability (sweet32 dependant on implemntation), 
the rest I just added to the list as they are old...

also you'll want to complie a custom version of openssl with all ciphers enabled, you can install it to a diry ssl dir, 
most distros won't ship with an openssl binary that has support for the ciphers above. 
