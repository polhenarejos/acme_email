# ACME Email S/MIME Client
ACME Email Client for **EmailReply-00 Challenge** to obtain S/MIME certificates.

The ACME Email S/MIME client is designed to facilitate the ACME Email Challenge for S/MIME certification. It operates in accordance with RFC 8823 *[Extensions to Automatic Certificate Management Environment for End-User S/MIME Certificates](https://datatracker.ietf.org/doc/html/rfc8823 "Extensions to Automatic Certificate Management Environment for End-User S/MIME Certificates")*, an extension to the ACME protocol [[RFC 8555](https://tools.ietf.org/html/rfc8555 "RFC 8555")].

Utilizing the [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server"), the ACME Email S/MIME Client can acquire S/MIME certificates through Certbot. These certificates enable the signing of emails, PDFs, DOCX files, etc., ensuring the integrity of the source and authorship. Unlike other platforms that require payment for these certificates, [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server") offers them **for free**.

## Motivation
The Let's Encrypt ACME system represents a significant advancement in web security. However, it lacks provisions for extending security measures to email and document signing. While the roadmap of Let's Encrypt remains unclear in this regard, S/MIME certificates seem to be a logical progression.

RFC 8823 outlines the procedure for validating the authenticity of an email, albeit without verifying the identity of the subject behind the email address, only the recipient. Similar to the ACME HTTPS specification, which does not validate the identity of the company behind a domain, the ACME Email S/MIME specification validates the authenticity of a specific email address.

We have implemented the ACME server at [CASTLE Platform®](https://www.castle.cloud/ "CASTLE Platform®"), adhering to and aligning with the specifications for obtaining S/MIME certificates. It's worth noting that [CASTLE Platform® Certification Authority](https://ca.castle.cloud/ "CASTLE Platform® CA") differs from Let's Encrypt, utilizing its own certification authority. Nevertheless, [CASTLE Platform® CA](https://ca.castle.cloud/ "CASTLE Platform® CA") upholds the same standards as other common CAs, ensuring compatibility and extensions. If [CASTLE Platform® CA](https://ca.castle.cloud/ "CASTLE Platform® CA") is trusted, the resulting S/MIME certificate is likely comparable to those obtained through paid CAs.

## Installation
Preferably, set up a Virtual Environment and install the package using the following commands:

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install .
```

These commands will install all necessary dependencies and required packages. Once the virtual environment is activated, you can proceed to use the client `cli.py`.

## How to use it
The ACME Email S/MIME client, implemented in `cli.py`, utilizes the Certbot framework for managing ACME protocols. Although the official software lacks support for S/MIME certification, we've devised a workaround by bypassing certain procedures, primarily the Certificate Signature Request (CSR), to adhere to standard specifications.

Here's how to use the client:

```plaintext
usage: cli.py [-h] [-e EMAIL] [-t] [--dry-run] [-n] [-c CONFIG_DIR] [-w WORK_DIR] [-l LOGS_DIR] [--agree-tos]
              [--contact CONTACT] [--imap] [--login LOGIN] [--password PASSWORD] [--host HOST] [--port PORT] [--ssl]
              [--smtp-method {STARTTLS,SSL,plain}] [--smtp-login SMTP_LOGIN] [--smtp-password SMTP_PASSWORD]
              [--smtp-host SMTP_HOST] [--smtp-port SMTP_PORT] [--no-passphrase] [--passphrase PASSPHRASE]
              [--usage {digitalSignature,contentCommitment,keyEncipherment,keyAgreement}] [--cert-path CERT_PATH]
              [--reason {unspecified,keycompromise,affiliationchanged,superseded,cessationofoperation}]
              [--key-path KEY_PATH] [--outlook] [--outlook-account OUTLOOK_ACCOUNT] [--tb] [--tb-unsafe]
              [--tb-profile TB_PROFILE] [--tb-bin TB_BIN]
              {cert,revoke,renew}

Requests a S/MIME certificate

positional arguments:
  {cert,revoke,renew}

optional arguments:
  -h, --help            show this help message and exit
  -e EMAIL, --email EMAIL
                        E-mail address to certify. Multiple e-mail addresses are allowed
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
  --agree-tos           Accepts Terms of Service
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
                        Passphrase to use for the PKCS12 generation. This passpharse will be used for private key
                        encryption
  --usage {digitalSignature,contentCommitment,keyEncipherment,keyAgreement}
                        Key usage for certificate. Multiple usages can be specified
  --cert-path CERT_PATH
                        Path where certificate is located
  --reason {unspecified,keycompromise,affiliationchanged,superseded,cessationofoperation}
                        Reason of revocation
  --key-path KEY_PATH   Path of private key location
  --outlook             Uses MAPI (Outlook) Authenticator for automatic reply
  --outlook-account OUTLOOK_ACCOUNT
                        Outlook account where the challenge is processed
  --tb                  Uses Thunderbird Authenticator for automatic reply
  --tb-unsafe           Run authenticator disabling security checks. USE WITH CAUTION.
  --tb-profile TB_PROFILE
                        Thunderbird profile where it runs
  --tb-bin TB_BIN       Thunderbird binary/executable path
```

The parameters are a blend of Certbot software and custom ones required for managing the S/MIME certification process. Multiple email addresses can be specified using the `--email` flag, useful for including multiple aliases under the same email account. Note that wildcard entries are not permitted. Additionally, please refer to the rate limits for the number of addresses allowed in a single certificate [here](https://acme.castle.cloud/documentation/rate-limits "Rate Limits").

### Key Usage
The ACME Email protocol allows specifying the key usage of the issued certificate. Currently, four (4) usages are permitted:

- For signing only:
  - `digitalSignature`: This usage is highly recommended as it enables digital signatures in S/MIME certificates for signing.
  - `contentCommitment` (formerly `nonRepudation`): It enables non-repudiation services to guarantee the authenticity of signed data.

- For encryption only:
  - `keyEncipherment`: The public key can be used to encrypt a symmetric key, which is then transferred to the target.
  - `keyAgreement`: The certificate may utilize a key agreement protocol to establish a symmetric key.

The client can specify multiple usages in a single certificate via the `--usage` flag. Use multiple `--usage` flags to indicate multiple usages (e.g., `--usage digitalSignature --usage keyEncipherment`).

If no `--usage` flag is specified, the ACME server will issue a certificate with `digitalSignature`, `contentCommitment`, and `keyEncipherment` by default.

No other extensions are allowed in the CSR. Any CSR with extensions different from `keyUsage` and `subjectAltNames` will be rejected.

If `--key-path` is used for the `cert` command, the new certificate will contain the same public key corresponding to the specified private key. This is useful for renewals with the same public key.

### Example

#### Using IMAP authenticator
To obtain an S/MIME certificate with the IMAP authenticator, the process is automated, requiring minimal user intervention. Here's an example command:

```bash
python3 cli.py cert --config-dir . --work-dir . --logs-dir . -e address@domain.com --contact contact@anotherdomain.com --imap --login imap_user --password imap_password --host imap.domain.com --ssl --smtp-method STARTTLS --smtp-port smtp_port --smtp-host smtp.domain.com
```

Explanation of parameters:
- `-e address@domain.com`: The email address to certify.
- `--contact contact@anotherdomain.com`: Contact address for receiving notifications related to the account.
- `--imap --login imap_user --password imap_password --host imap.domain.com --ssl`: IMAP settings for authentication. Replace `imap_user`, `imap_password`, and `imap.domain.com` with your IMAP login credentials and server information. SSL is enabled for secure communication.
- `--smtp-method STARTTLS --smtp-port smtp_port --smtp-host smtp.domain.com`: SMTP settings for authentication. Replace `smtp_port` and `smtp.domain.com` with your SMTP port and server information. STARTTLS method is used for secure communication.

Notes:
1. If SMTP credentials are not provided, the IMAP credentials for the SMTP client will be used.
2. This authenticator works with "normal" email accounts and does not support OAuth login (e.g., Gmail).
3. The ACME messages are retrieved from the INBOX. Ensure correct spam filtering or pre-filtering rules are in place.
4. If issues arise, consider using the interactive authenticator.

If the process is successful, the ACME server will grant the request and issue a certificate. The certificate will be downloaded automatically and stored in a PKCS12 container, which includes the private key. It's highly recommended to protect the PKCS12 container with a passphrase. You can specify the passphrase using `--passphrase <the_passphrase>` to automate the process.

#### Using MAPI/Outlook authenticator
With this authenticator, no login and password are provided in the CLI since it uses Outlook client to manage the account. This authenticator works with OAuth email providers.

To utilize the MAPI authenticator for automatically replying to the ACME Email Challenge without user interaction, follow these steps:

1. Open your Outlook client **with Administrator privileges** (right-click on the Outlook client --> Run as Administrator).
2. Select the Inbox of the account to be challenged. Ensure that the connection with your IMAP provider is properly configured.
3. Execute the client `cli.py` with the `--outlook` and `--outlook-account ACCOUNT` parameters, where `ACCOUNT` is the name of your Outlook account.

For example:

```bash
python cli.py cert -e address@domain.com --outlook --outlook-account MyPersonalAccount
```

Note: Due to limitations in Certbot, Outlook must run with Administrator rights.

#### Using Thunderbird authenticator
With this authenticator, no login and password are provided in the CLI since it uses Thudnerbird client to manage the account. This authenticator works with OAuth email providers.

To utilize the Thunderbird authenticator for automatically replying to the ACME Email Challenge without user interaction, follow these steps:
1. Open your Thunderbird client.
2. Execute the client `cli.py` with the `--tb` parameter.
3. In case of security error, pass the `--tb-unsafe` parameter to bypass these checks.
4. After receiving the ACME challenge, a pop-up will appear with the response in the body. Just click on Send and **do not modify any value**.

For example:


```bash
python cli.py cert -e address@domain.com --tb --tb-unsafe
```

#### Using interactive authenticator
**IMPORTANT: This method is not recommended, as it does not performs any authentication check (such as DKIM or S/MIME). These checks MUST be carried out by the user manually.**

For obtaining an S/MIME certificate with the interactive authenticator, follow these steps:

```bash
python3 cli.py cert --config-dir . --work-dir . --logs-dir . -e address@domain.com --contact contact@anotherdomain.com --usage digitalSignature --usage keyEncipherment
```

Explanation of parameters:
- `-e address@domain.com`: The email address to certify.
- `--contact contact@anotherdomain.com`: Contact address for receiving notifications related to the account.
- `--usage digitalSignature --usage keyEncipherment`: Specifies the key usages for the certificate.

After executing this command, the client will negotiate with [CASTLE Platform® ACME Server](https://acme.castle.cloud/ "CASTLE Platform® ACME Server") to obtain an S/MIME certificate. Here's what you need to do next:

1. An email will be sent to `address@domain.com` with a challenge subject.
2. The subject will have the form of `ACME: <token>`. You need to wait for the token to be received in the email inbox.
3. Copy the **entire** subject (including the `ACME: ` part) and paste it into the client terminal.
4. The client will generate the **challenge response** using the provided token. This response will have the form `-----BEGIN ACME RESPONSE-----...-----END ACME RESPONSE-----`.
5. Copy the response and reply to the ACME email you received. Paste the challenge response in the **top of the message's body** and send it back to the ACME server.

It's crucial to note that your private key is not transmitted to the ACME server or over the internet at any point. The CSR contains your public key, linked to your private key, and the ACME server generates the public certificate based on it, without requiring the private key.

Also, remember that private and public keys are generated automatically, so you don't need to worry about that part of the process.

### Current Features
It sounds like the ACME Email S/MIME client is quite versatile and feature-rich. Here's a summary of its capabilities:

- **Local Private Key Generation**: The client generates the private key locally on the user's system.
- **S/MIME Challenge Support**: Implements the S/MIME challenge as defined in RFC 8823.
- **PKCS12 Certificate Storing**: Stores certificates in PKCS12 format, including the embedded private key.
- **Certificate Revocation**: Supports revocation of certificates.
- **Adjustable RSA Key Bit-length**: Allows customization of the RSA key bit-length, including options like 2048 (default), 4096, etc.
- **Customizable Key Usage**: Users can specify key usages for the certificate, including digitalSignature, keyEncipherment, contentCommitment, and/or keyAgreement.
- **Automation Options**: Supports both fully automated and interactive modes.
- **IMAP and SMTP Support**: Offers support for automated ACME replies via IMAP and SMTP.
- **MAPI/Outlook Support**: Provides support for automated ACME replies using MAPI/Outlook.
- **Thunderbird Support**: Provides support for automated ACME replies using Thunderbird.
- **DKIM and S/MIME Checks**: Performs DKIM and S/MIME checks for message authentication.
- **Multiple Email Addresses**: Can include multiple email addresses in a single certificate.
- **Reusable Private Key**: Allows reuse of private (and public) keys for multiple certificates.
- **Staging ACME Server**: Supports a staging ACME server for testing environments.
- **User Interface Options**: Supports an interactive text UI or can be driven entirely from the command line.
- **Open Source**: Free and open-source software, developed with Python.

Overall, these features make the ACME Email S/MIME client a comprehensive tool for managing S/MIME certificates with various customization and automation options.

## TL;DR (some technical aspects)
# Summary:

Certbot is a powerful software for managing the ACME procedure, but it only supports "dns" Identifier Types in the CSR, which is incompatible with S/MIME certificates requiring "email" Identifier Types. To address this, the client provides a workaround using the `--csr` parameter to accept external CSRs. The client comprises three main modules:

1. **Authenticator Plugin**:
   - **IMAP**: Automatically handles ACME challenge responses by creating dynamic IMAP and SMTP clients.
   - **Interactive**: Requires user intervention for ACME challenge responses, but lacks authentication checks.
2. **Installation Plugin**: Generates PKCS12 containers with private keys and certificates.
3. **Challenges**: Defines the EmailReply-00 challenge specified in RFC 8823.

Additionally, due to Certbot's requirements, the CSR must include both `RFC822Name` and `DNSName` in the Subject Alternative Names. The client's flexibility allows users to customize their code while leveraging Certbot's functionality. If Certbot were to support "email" Identifier Types and ACME S/MIME challenges in the future, this workaround may become unnecessary.

## License:
The code in this repository is licensed under GPLv3.

## About:
The ACME E-mail S/MIME Client and ACME E-mail S/MIME Server are components of the CASTLE Platform®, developed by the Centre Tecnològic de Telecomunicacions de Catalunya (CTTC), a non-profit research institution based in Castelldefels, Spain. CTTC focuses on communication system technologies and geomatics research.

**Maintainer:** Pol Henarejos (pol.henarejos@cttc.es)