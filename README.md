# pyCertLogo
OpenSSL config-file generator to embed pictures (GIF, JPEG, SVG, PNG, PDF) or audio (MP3) files into X.509 digital certificates.
Implements X.509 Public Key Infrastructure (PKI)'s [RFC 3709]([https://](https://www.rfc-editor.org/rfc/rfc3709)) ("Logotypes in X.509 Certificates") and [RFC 6170](https://www.rfc-editor.org/rfc/rfc6170) ("Certificate Image").

Includes a class to manipulate Object Identifiers (OIDs) and several classes to manipulate logos within X.509 certificates.
Its main purpose is, given a series of logotypes (either images and audio), to generate an OpenSSL configuration-file extension to include in the template for generating a specific X.509 certificate.
