# ACME Email S/MIME Client
ACME Email Client for **EmailReply-00 Challenge** to obtain S/MIME certificate.

Let's Encrypt ACME for retrieving HTTPS certificates are widely used and it defined a standard by obtaining certificates in an automatized way. ACME Email S/MIME client aims at performing the same protocol but for S/MIME certification. It is based on *[Extensions to Automatic Certificate Management Environment for end-user S/MIME certificates](https://tools.ietf.org/html/draft-ietf-acme-email-smime "Extensions to Automatic Certificate Management Environment for end-user S/MIME certificates")* draft specification, which is an extension to the ACME protocol [[RFC 8555](https://tools.ietf.org/html/rfc8555 "RFC 8555")]. Despite it is a draft, it is the only living specification that describes the procedure for obtaining automatic S/MIME certificates.

With CASTLE Platform® ACME Server, ACME Email S/MIME Client can obtain S/MIME certificates by using Certbot. With S/MIME certificates, e-mails, pdf, docx, etc. can be signed to proof the integrity of the source and authorship. Despite other platforms that require to pay for obtaining these certificates, CASTLE Platform® ACME Server offers it **by free**.

## Why
Let's Encrypt ACME system is robust and represents a major step for securing the web. However, there is no possibility to extend it to e-mail and document signing. I do not know which is their roadmap, but I think that S/MIME certificates are the next natural step.

Despite the ACME e-mail S/MIME specification is still under draft, it describes the procedure to validate the authenticity of an e-mail. It does not validates the identify of the subject behind the e-mail address, only the recipient. As with the ACME HTTPS specification, which does not validate the identify of the company behind a domain, ACME e-mail S/MIME specification describes the validity of a particular e-mail address.

We implemented the ACME server at CASTLE Platform® and it fits and follows the specifications for obtaining S/MIME certificates. Obviously, CASTLE Platform® Certification Authority is not the same as Let's Encrypt, it uses its own. Fortunately, CASTLE Platform® CA follows the same standards as other common CA, with the same compatibilities and extensions. If CASTLE Platform® CA is trusted, the obtained S/MIME certificate is likely similar to the ones obtained through paying CA.
