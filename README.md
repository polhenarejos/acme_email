# ACME Email S/MIME Client
ACME Email Client for **EmailReply-00 Challenge** to obtain S/MIME certificate.

Let's Encrypt ACME for retrieving HTTPS certificates are widely used and it defined a standard by obtaining certificates in an automatized way. ACME Email S/MIME client aims at performing the same protocol but for S/MIME certification. It is based on *[Extensions to Automatic Certificate Management Environment for end-user S/MIME certificates](https://tools.ietf.org/html/draft-ietf-acme-email-smime "Extensions to Automatic Certificate Management Environment for end-user S/MIME certificates")* draft specification, which is an extension to the ACME protocol [[RFC 8555](https://tools.ietf.org/html/rfc8555 "RFC 8555")]. Despite it is a draft, it is the only living specification that describes the procedure for obtaining automatic S/MIME certificates.

With CASTLE Platform® ACME Server, ACME Email S/MIME Client can obtain S/MIME certificates by using Certbot. With S/MIME certificates, e-mails, pdf, docx, etc. can be signed to proof the integrity of the source and authorship. Despite other platforms that require to pay for obtaining these certificates, CASTLE Platform® ACME Server offers it **by free**.

## Why
Let's Encrypt ACME system is robust and represents a major step for securing the web. However, there is no possibility to extend it to e-mail and document signing. I do not know which is their roadmap, but I think that S/MIME certificates are the next natural step.

Despite the ACME e-mail S/MIME specification is still under draft, it describes the procedure to validate the authenticity of an e-mail. It does not validates the identify of the subject behind the e-mail address, only the recipient. As with the ACME HTTPS specification, which does not validate the identify of the company behind a domain, ACME e-mail S/MIME specification describes the validity of a particular e-mail address.

We implemented the ACME server at CASTLE Platform® and it fits and follows the specifications for obtaining S/MIME certificates. Obviously, CASTLE Platform® Certification Authority is not the same as Let's Encrypt, it uses its own. Fortunately, CASTLE Platform® CA follows the same standards as other common CA, with the same compatibilities and extensions. If CASTLE Platform® CA is trusted, the obtained S/MIME certificate is likely similar to the ones obtained through paying CA.

## How to use it
ACME E-mail S/MIME client uses the Certbot framework for managing ACME protocols. However, the official software does not provide support for S/MIME certification. To cirvument this issue, we bypass some procedures (CSR mainly) to acomplish standard specifications. `cli.py` performs all this stuff by generating CSR with the correct extension and executes Certbot with the correct parameters.

To use it:
    usage: cli.py [-h] -e EMAIL [-t] [--dry-run] [-n] [-c CONFIG_DIR] [-w WORK_DIR] [-l LOGS_DIR] [--agree-tos AGREE_TOS] [--contact CONTACT] {cert,revoke,renew}
    
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
	  
Some of the parameters are shared by Certbot software, since it manages the protocol stack and data flow between the client and the ACME server. Sooner more parameters will be added.

### Example
For obtaining an S/MIME certificate
`python3 cli.py cert --config-dir . --work-dir . --logs-dir . -e trocotronic@redyc.com --contact trocotronic@redyc.com`
