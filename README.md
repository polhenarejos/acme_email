# ACME Email S/MIME Client
ACME Email Client for **EmailReply-00 Challenge** to obtain S/MIME certificate.

Let's Encrypt ACME for retrieving HTTPS certificates are widely used and it defined a standard by obtaining certificates in an automatized way. ACME Email S/MIME client aims at performing the same protocol but for S/MIME certification. It is based on RFC 8823 *[Extensions to Automatic Certificate Management Environment for End-User S/MIME Certificates](https://datatracker.ietf.org/doc/html/rfc8823 "Extensions to Automatic Certificate Management Environment for End-User S/MIME Certificates")*, which is an extension to the ACME protocol [[RFC 8555](https://tools.ietf.org/html/rfc8555 "RFC 8555")].

With [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server"), ACME Email S/MIME Client can obtain S/MIME certificates by using Certbot. With S/MIME certificates, e-mails, pdf, docx, etc. can be signed to proof the integrity of the source and authorship. Despite other platforms that require to pay for obtaining these certificates, [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server") offers it **by free**.

## Why
Let's Encrypt ACME system is robust and represents a major step for securing the web. However, there is no possibility to extend it to e-mail and document signing. I do not know which is their roadmap, but I think that S/MIME certificates are the next natural step.

RFC 8823 describes the procedure to validate the authenticity of an e-mail. It does not validates the identify of the subject behind the e-mail address, only the recipient. As with the ACME HTTPS specification, which does not validate the identify of the company behind a domain, ACME e-mail S/MIME specification describes the validity of a particular e-mail address.

We implemented the ACME server at [CASTLE Platform®](https://www.castle.cloud/ "CASTLE Platform®") and it fits and follows the specifications for obtaining S/MIME certificates. Obviously, [CASTLE Platform® Certification Authority](https://ca.castle.cloud/ "CASTLE Platform® CA") is not the same as Let's Encrypt, it uses its own. Fortunately, [CASTLE Platform® CA](https://ca.castle.cloud/ "CASTLE Platform® CA") follows the same standards as other common CA, with the same compatibilities and extensions. If [CASTLE Platform® CA](https://ca.castle.cloud/ "CASTLE Platform® CA") is trusted, the obtained S/MIME certificate is likely similar to the ones obtained through paying CA.

## Installation
It is preferably to create a Virtual Environment and install the package as follows:

    python3 -m venv venv
    source venv/bin/activate
    pip3 install .
    
It will install all dependancies and required packages. With the virtual environment activated, you can continue using the client `cli.py`.
             
## How to use it
ACME E-mail S/MIME client uses the Certbot framework for managing ACME protocols. However, the official software does not provide support for S/MIME certification. To circumvent this issue, we bypass some procedures (CSR -- Certificate Signature Request mainly) to acomplish standard specifications. `cli.py` performs all this stuff by generating CSR with the correct extension and executes Certbot with the correct parameters.

To use it:

    usage: cli.py [-h] -e EMAIL [-t] [--dry-run] [-n] [-c CONFIG_DIR] [-w WORK_DIR] [-l LOGS_DIR] [--agree-tos AGREE_TOS] [--contact CONTACT] [--imap] [--login LOGIN] [--password PASSWORD] [--host HOST] [--port PORT] [--ssl]
              [--smtp-method {STARTTLS,SSL,plain}] [--smtp-login SMTP_LOGIN] [--smtp-password SMTP_PASSWORD] [--smtp-host SMTP_HOST] [--smtp-port SMTP_PORT] [--no-passphrase] [--passphrase PASSPHRASE]
              [--usage {digitalSignature,contentCommitment,keyEncipherment,keyAgreement}]
              {cert,revoke,renew}

    
    Requests a S/MIME certificate
    
    positional arguments:
      {cert,revoke,renew}
    
    optional arguments:
      -h, --help            show this help message and exit
      -e EMAIL, --email EMAIL
                            E-mail of the issued certificate
      -t, --test            Tests the certification from a staging server
      --dry-run             Do not store any file. For testing
      -n, --non-interactive
                            Runs the certification without any user interaction
      -c CONFIG_DIR, --config-dir CONFIG_DIR
                            Configuration directory
      -w WORK_DIR, --work-dir WORK_DIR
                            Working directory
      -l LOGS_DIR, --logs-dir LOGS_DIR
                            Logs directory
      --agree-tos AGREE_TOS
                            Logs directory
      --contact CONTACT     Contact e-mail for important account notifications
      --imap                Uses IMAP Authenticator for automatic reply
      --login LOGIN         IMAP login
      --password PASSWORD   IMAP password
      --host HOST           IMAP server host
      --port PORT           IMAP server port. If empty, it will be auto-detected
      --ssl                 IMAP SSL connection
      --smtp-method {STARTTLS,SSL,plain}
                            SMTP method {STARTTLS,SSL,plain}
      --smtp-login SMTP_LOGIN
                            SMTP login. If empty, IMAP login will be used
      --smtp-password SMTP_PASSWORD
                            SMTP password. If empty, IMAP password will be used
      --smtp-host SMTP_HOST
                            SMTP server host
      --smtp-port SMTP_PORT
                            SMTP server port. If empty, it will be auto-detected
      --no-passphrase       PKCS12 is stored without passphrase. Use with CAUTION: the PKCS12 contains the private key
      --passphrase PASSPHRASE
                            Passphrase to use for the PKCS12 generation. This passpharse will be used for private key encryption
      --usage {digitalSignature,contentCommitment,keyEncipherment,keyAgreement}
                            Key usage for certificate. Multiple usages can be specified
	  
Some of the parameters are shared by Certbot software, since it manages the protocol stack and data flow between the client and the ACME server. Sooner more parameters will be added.

Multiple email addresses can be specified. All these addresses will be added to `subjectAltNames` extension with the identifier `email` into a single certificate. **No wildcards are allowed**. This is useful when you use multiple alias under the same email account. Keep in mind that there are some rate limits on the number of addresses that can be included in a single certificate. Consult them at [Rate Limits](https://acme.castle.cloud/documentation/rate-limits "Rate Limits"). To specify multiple email addresses use `--email` flag so many times as needed.


### Key Usage
The ACME Email protocol defines the possibility to specify the key usage of the issued certificate. Currently, four (4) usages are allowed:
* For signing only:
  * `digitalSignature`: this usage is highly recommended, as it enables the digital signature in S/MIME certificates for signing.
  * `contentCommitment` (formerly `nonRepudation`): it enables non-repudiation services to guarantee the authenticity of signed data. 
* For encryption only:
  * `keyEncipherment`: the public key can be used to encrypt a symmetric key, which is transferred to the target. 
  * `keyAgreement`: the certificate may use a key agreement protocol to establish a symmetric key.

The client can specify multiple usages in a single certificate vía `--usage` flag. Use multiple `--usage` to specify multiple usages (for example, `--usage digitalSignature --usage keyEncipherment`). 

If no `--usage` flag is specified, the ACME server will issue a certificate with `digitalSignature`, `contentCommitment` and `keyEncipherment` by default.

No other extension are allowed in the CSR. Any CSR with extensions different from `keyUsage` and `subjectAltNames` will be rejected.

### Example

#### Using IMAP authenticator
For obtaining an S/MIME certificate with IMAP authenticator. With this authenticator, all the procedure is performed automatically. IMAP and SMTP clients are created dynamically and the ACME challenge is answered without user intervention. 

For example:

`python3 cli.py cert --config-dir . --work-dir . --logs-dir . -e address@domain.com --contact contact@anotherdomain.com --imap --login imap_user --password imap_password --host imap.domain.com --ssl --smtp-method STARTTLS --smtp-port smtp_port --smtp-host smtp.domain.com`

where `address@domain.com` is the e-mail address to certify and `contact@anotherdomain.com` is just the contact address for receiving notifications related with the account. Contact address is only used the first time. It can be ommitted in subsequent calls.

This authenticator creates dynamic IMAP and SMTP clients for getting the token from the ACME e-mail, generate the authentication and reply to the ACME server with the ACME response. All the process is transparent and smooth to the user. 
Notes:
1. If no SMTP credentials are provided, IMAP credentials for SMTP client will be used.
2. This authenticator works for "normal" e-mail accounts. It does not work with e-mail providers that have OAuth login (i.e., no GMail).
3. The ACME message are catched from INBOX. It will not work if you have a misconfigured spam filtering or have pre-filtering rules.
4. In case it does not work, use interactive authenticator.

If everything goes well, the ACME server will grant your request and will issue a certificate. This certificate will be downloaded automatically and the client will put in a PKCS12 container. The client also will put the private key in the PKCS12 container. The PKCS12 container is a standard object, used for importing public and private keys to the Keychain. Often is used by e-mail clients for selecting the S/MIME certificate, used for signature and encryption. 

You can optionally protect the PKCS12 container with a passphrase. Since it contains your private key, **it is highly recommended** to protect the PKCS12 container with a strong passphrase. The client will prompt you for a passphrase before generating the PKCS12, if no `--pasphrase` is specified. If you aim at authomatizing the whole process, use the flag `--passphrase <the_passphrase>` to specify the secret passphrase.

#### Using interactive authenticator
**IMPORTANT: This method is not recommended, as it does not performs any authentication check (such as DKIM or S/MIME). These checks MUST be carried out by the user manually.**

For obtaining an S/MIME certificate with interactive authenticator. 

`python3 cli.py cert --config-dir . --work-dir . --logs-dir . -e address@domain.com --contact contact@anotherdomain.com --usage digitalSignature --usage keyEncipherment`

where `address@domain.com` is the e-mail address to certify and `contact@anotherdomain.com` is just the contact address for receiving notifications related with the account. Contact address is only used the first time. It can be ommitted in subsequent calls.

After this, the client will negotiate with [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server") for obtaining an S/MIME certificate. 
1. An e-mail will be send to `address@domain.com` with a challenge subject. The client will wait for the token you will receive in the `address@domain.com`.
2. The subject has the form of `ACME: <token>`. The `<token>` part is needed for passing the challenge.
3. Copy the **entire** subject (with the `ACME: `part included) and paste it to the client terminal. 
4. With the `<token>`you provided, the client will generate the **challenge response**, which has the form `-----BEGIN ACME RESPONSE-----...-----END ACME RESPONSE-----`.
5. Copy the response and reply the ACME e-mail you received. Paste the challenge response in the **top of the message's body** and send it back to the ACME server.

**IMPORTANT: Remind that your private key is not transmitted to ACME server, nor flows through internet at any time. The CSR contains your public key linked to your private key and the ACME server generates the public certificate based on it, without the need of the private key.**

_(Reminder: private and public keys are generated automatically, you do not have to worry about that.)_

### Current Features
* The private key is generated locally on your system.
* S/MIME challenge, defined at RFC 8823.
* PKCS12 certificate storaging, with embedded private key.
* Can revoke certificates.
* Adjustable RSA key bit-length (2048 (default), 4096, ...).
* Customizable key usage for the certificate: digitalSignature, keyEncipherment, contentCommitment and/or keyAgreement can be specified.
* Fully automated or interactive.
* IMAP and SMTP support for automated ACME replies.
* DKIM and S/MIME checks for message authentication.
* Multiple email addresses in a single certificate.
* Staging ACME server for test environments.
* Supports an interactive text UI, or can be driven entirely from the command line.
* Free and Open Source Software, made with Python.

## TL;DR (some technical aspects)
Certbot is a magnific software. It manages the ACME procedure and gives a support for customized plugins. However, it only supports "dns" Identifier Types in the CSR and here is where the problem arises. S/MIME certificates (and also specifications) require that Identifier Types **must be** "email". The ACME server could replace "dns" for "email" in the CSR but this is not possible, as the CSR is signed with the private key and it is unalterable. 

Fortunately, Certbot supports the `--csr` parameter, which allows to provide an external CSR instead of auto-generated CSR. 

The rest of the client is composed by three modules: 

1. Authenticator plugin: it performs the authentication task, generating the ACME response by using the `<token>` provided in the subject. Two authenticators are provided:
   1. IMAP: it creates dynamic IMAP and SMTP clients for ACME message interception, token catching and automatic response to ACME server. No user intervention is needed.
   2. Interactive: it requires user intervention by pasting the token, copying the ACME response and replying to the ACME server via e-mail. **This method is not recommended, as it does not performs any authentication check (such as DKIM or S/MIME). These checks MUST be carried out by the user manually.**
2. Installation plugin: it generates the PKCS12 container with the private key and certificate.
3. Challenges: it defines the EmailReply-00 challenge, described at RFC 8823. 

Thanks to this, we are able to write on our own code and leave the Certbot code unmodified. Of course, if in a future Certbot supports "email" Identifier Type and ACME S/MIME challenges, all this repository will be useless. In the meantime, you can use it.

## License
All the code in this repository is under GPLv3 license.

## About 
ACME E-mail S/MIME Client and ACME E-mail S/MIME Server are part of the [CASTLE Platform®](https://www.castle.cloud/ "CASTLE Platform®"), a platform of the [Centre Tecnològic de Telecomunicacions de Catalunya (CTTC)](https://www.cttc.es "CTTC"). 

Maintainer:
* Pol Henarejos (pol.henarejos@cttc.es).

The Centre Tecnològic de Telecomunicacions de Catalunya (CTTC) is a non-profit research institution based in Castelldefels (Barcelona), resulting from a public initiative of the Regional Government of Catalonia (Generalitat de Catalunya).

Research activities at the CTTC, both fundamental and applied, mainly focus on technologies related to the physical, data-link and network layers of communication systems, and to the Geomatics.
