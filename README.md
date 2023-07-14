# pyCertLogo
OpenSSL template file generator for embedding pictures or audio logotypes into X.509 digital certificates.
This tool's  main purpose is help with automated generation of OpenSSL templates for embedding specific logotypes (either images and audio, cfr. below) into either public-key and attribute certificates conforming with ITU-T X.509 / [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) standard.

### Rationale
Certificate logos/logotypes augment the UX of end-user applications and improve the overall *digital trust*, as they provide trusted visual representations of people, organizations, website and/or IT systems which digital certificates are bound to. The digital signature of a CA over such digital certificate also protects the embedded logos/logotypes, thus ensuring their integrity and authenticity together with the rest of the certified data (e.g. a public key or attribute).
In order to effectively exploit this "side-channel trust", either the digital signing or the digital signature validation processes should support parsing the logo(s) from the certificate payload (further details in the 7 examples below).

### Standards
Implements X.509 Public Key Infrastructure (PKI) standard [RFC 9399](https://www.rfc-editor.org/rfc/rfc9399) (“Logotypes in X.509 Certificates”) from May 2023, which obsoletes both [RFC 3709](https://www.rfc-editor.org/rfc/rfc3709) and [RFC 6170](https://www.rfc-editor.org/rfc/rfc6170).
This may also be used for *electronic* certificates, pursuant to [Regulation (UE) №910/2014 “**eIDAS**”](https://digital-strategy.ec.europa.eu/en/policies/eidas-regulation), currently at its final stages of legislative review to transit into **eIDAS2**, which norms European electronic signatures (e-signing), seals (e-sealing), attestations of attributes, electronic ledgers (DLTs), website authentication certificates (WAC), as well as other types of electronic trust services.
Other relevant technical standards where certificate logotypes may improve the overall UX are those on advanced digital signatures (including advanced e-signatures/seals) on additional file formats:
  * **PDF**: either Adobe's *PDF Signature* ([ISO 32000-2](https://www.iso.org/standard/75839.html)), and “**PAdES**” from the ETSI [EN 319-142](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.02.01_60/en_31913201v010201p.pdf) family;
  * **XML**: either W3C's *XML Digital Signature* ([XML-DSIG](https://www.w3.org/TR/xmldsig-core2/)), and “**XAdES**” from the ETSI [EN 319-132](https://www.etsi.org/deliver/etsi_en/319100_319199/31913201/01.02.01_60/en_31913201v010201p.pdf) family;
  * **PKCS#7**, or “**CAdES**” from the ETSI [EN 319-122](https://www.etsi.org/deliver/etsi_en/319100_319199/31912201/01.03.01_60/en_31912201v010301p.pdf) family;
  * **JSON**: either *JSON Web Signature* (**JWS** from [RFC 7515](https://rfc-editor.org/rfc/rfc7515)), and “**JAdES**” from the ETSI [TS 119-182](https://www.etsi.org/deliver/etsi_ts/119100_119199/11918201/01.01.01_60/ts_11918201v010101p.pdf) family.


### Applications
A non-exhaustive list of applications potentially benefiting from the embedding of images or audio content as certificate logos/logotypes includes:
  1. Compositing, on an electronically signed (e-sign) PDF document, the scanned raster of the signatory (natural person)'s **handwritten signature**, derived from the e-certificate itself. When the e-signed document is printed on paper or viewed on screen, this provides a convincing visual representation of an handwritten signature to relying parties. Besides, the signature is not pasted from a potentially untrusted image under the control of anyone, but rather it is parsed from the e-certificate itself as part of the e-signing process, thus that is still under the control of the signatory. The signature's raster is indeed a public payload, yet its association with the e-certificate's public key (and, reflectively, with the e-signature itself) is cryptographically sound: relying parties who trust an e-signing process designed to enable a "certificate logotype workflow" will also trust the authenticity of the signature raster. The e-signature itself, however, is the one legally binding evidence on the document. Cfr. ETSI [EN 319-142](https://www.etsi.org/deliver/etsi_en/319100_319199/31914201/01.01.01_60/en_31914201v010101p.pdf) “PAdES” standards' family for more details.
  2. Compositing, on an electronically sealed (e-seal) PDF document, the **organizationl logo**types (legal person) that visually improve both the document's integrity and authenticity. Cfr. considerations from the previous bullet point.
  3. Extract, from the identification (IdV) certificate in an electronic identification (eID) means (e.g. an **e-Passport**, or the Italian **CIE** eID card), the owner's ICAO-compliant photograph raster. The Authority that e-sealed the above certificate has previously and authoritatively identity-proofed the subject. Relying parties may trust such cryptographic binding to identify the subject, by comparing the photograph embedded into the IdV certificate with a real-time scan of the subject's appearence, acquired during automated or manual inspection by a (e.g. customs) officer. Comparison with the printed photograph on the eID card may also be used to authenticate the ID/travel document itself. This process augments and builds from eID [Passive Authentication (PAC)](https://www.bsi.bund.de/EN/Themen/Oeffentliche-Verwaltung/Elektronische-Identitaeten/Elektronische-Ausweisdokumente/Sicherheitsmechanismen/Passive-Authentication/passive-authentication_node.html) method (cfr. BSI [TR-03110](https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Technische-Richtlinien/TR-nach-Thema-sortiert/tr03110/TR-03110_node.html) standard).
  4. The web browser where a given website (or any other online HTTPS resource) is visited displays the logotype of such trusted website's organization directly parsing it from its website authentication certificate (WAC), or "TLS certificate". In this case the logo extracted from the validated WAC provides improved user experience (UX) on the association of the visited page with its legitimate owner (instead of relying on `commonName` or lenghtier-to-read distinguished names in the WAC). Again, relying parties trusting the web browser's WAC validation process should trust the authenticity of websites with such valid WACs.
  5. Applications performing identification/authentication/authorization processes, e.g. by means of XML/JSON/JWS based messaging like SAML/OAuth/OpenID Connect (OIDC) assertons, tokens, decentralized identifiers (**DID**s), transactions on databases/e-ledgers/**blockchain**s, as well as **attestation**s **of attributes** may carry pictures representing such proocesses, as well as the logotypes of their service/identity providers and relying parties. These logos may be displayed by web/mobile applications to improve visual identification of such parties and provide better UX and digital trust to the users.
  6. Web/mobile apps processing e-money, **payment card**s or **cryptocurrency** transactions may display the logos from either the card's **EMV** circuit, the issuing bank, the merchant(s), the cryptocurrency system *and* the crypto-wallet itself, again, in order to improve the overall UX and provide real-time "visual trust" to such transactions.
  7. Operating system (OS) parsing an e-signed/sealed file displays the file via an icon on the OS destkop GUI, which either resembles the file format *and* previews the file contents themselves (usually from its first page). The certificate parsed from the e-signature/seal may be superimposed over the icon in the shape of one or multiple badges. This improves the users' visibility as to the file being digitally signed, and to the technical and legal meaning of such signing process (e.g. whether the file has a single, multiple or parallel signatures, whether they are e-signatures/seals, q-signatures/seals, etc.).


## Usage ##
The first argument to pass is the pathname an OpenSSL-valid configuration file (may also be empty when initially written by the present tool, otherwise data are just appended to it). Other arguments are optional (but at least one is required):
```filename           Filename to output (append) the OpenSSL template, divided in sections;
[-i URIorFilename]        Filename or URI where a valid Issuer logotype can be found;
[-s URIorFilename]        Filename or URI where a valid Subject logotype can be found;
[-c URIorFilename]        Filename or URI where valid Community logotype(s) can be found (can be invoked multiple times);
[-O oid -o URIorFileame]      OID and filename (or URI) where any other logotype(s) can be found (can be invoked multiple times);.
```

### Examples
Certiicate logotypes for the seven applications above may be generated using `pyCertLogo` using the following suggested commands:
  1. Electronic trust service provider (eTSP) issuing e-signing certificate with the eTSP's own logo as Issuer logotyoe (`-i`/`--issuer`) and a raster image representing the signer's handwritten signature (e.g. a monochromatic transparent PNG) as the Subject logotype (`-s`/`--subject`). A Qualified trust service provider (QTSP) may add the [eIDAS trust mark](https://digital-strategy.ec.europa.eu/en/policies/eu-trust-mark), pursuant to [CIR (EU) 2015/806](http://eur-lex.europa.eu/legal-content/EN/TXT/?qid=1441782918257&uri=CELEX:32015R0806), as another logotype  (`-O` *and* `-o`) associated to a reserved OID by the European Commission.
  2. eTSP issuing e-sealing certificate with the eTSP's own logo as Issuer logotyoe (`-i`) and a raster image representing the seal-creator organization's logo as the Subject logotype (`-s`). Optionally, a QTSP may add the [eIDAS trust mark](https://digital-strategy.ec.europa.eu/en/policies/eu-trust-mark) as another logotype  (`-O`+`-o`) associated to the aforementioned reserved OID.
  3. Authority governing an ID/eID means issues an IdV certificate using the Authority's own logo as Issuer logotype (`-i`), the eID subject's photograph as Subject logotype (`-s`) and, optionally, either the ICAO logo *and* the organization manufacturing the smartcard's logo as community logos (multiple `-c`/`--community`).
  4. eTSP issuing web access certificate (WAC) using the eTSP's own logo as Issuer logotype (`-i`), the website owner's own logo as Subject logotype (`-s`) and, optionally, the [CA/Browser Forum](https://cabforum.org/)'s own logo as Community (`-c`) or other logotype (`-o`+`-O`).
  5. The application e-seals every messages (e.g. SAML requests/responses/assertions, or OAuth/OIDC tokens) for authentication/integrity purposes, using the certificate's issuing CA's logo as Issuer logotype (`-i`), the application's (or the app owner's) own logo as Subject logotype (`-s`) and, optionally, either the logo of the identification/authentication/authorization framework (e.g. the **OAuth** logo) *and* specific federation (e.g. the **SPID** logo for the Italian eID) as either community (`-c`) or other logotype using reserved OIDs (multiple `-o`+`-O`).
  6. Authorization certificate for e-money transactions contains (references to) the card circuit (e.g. EMV)'s, the issuing central bank, or the crypto**wallet**'s own logo as Issuer logotype (`-i`), plus logos from either the payment card's merchant, the issuinb comercial bank, or the adopted cryptocurrency framework as Community logotype(s) (multiple `-c`).
  7. The certificate parsed from the e-signature/seal uses the issuing eTSP as Issuer logotype (`-i`), a visual identifier of the signatory/seal-creator's (e.g. its logo, the raster of a stamp from the organization, or the CEO's handwritten signature) as Subject logotype (`-s`), plus additional logos. To help blending such badges with different OS graphic backgrounds, a background picture may also be parsed from the certificate, which badges are composited over. Alternatively, an image representing the digital certificate itself (along with its SubjectDN, IssuerDN, expiration dates, etc.) may be included. These two options are embedded as other logotypes (`-o`+`-O`), with specific OIDs, repsectively `id-logo-background` and `id-logo-certImage`.


### Implementation details
Certificate logos may be either “directly” embedded in the X.509 certificate (i.e. they are base64-encoded then wrapped in BER by the certificate itself, which considerably increases the payload size), or “indirectly” referenced from the certificate: the latter means each logotype is externally provided content (e.g. uploaded on a CDN) whereby the certificate contains both that content's URI and one or more of its digests. In this case the certificate payload is not significantly increased, but at the expenses of the issuing CA, which should provide for the logotype(s)' online availability.

Currently supported file formats for certificate logotypes are SVG (and SVGZ), PNG, JPEG, PDF and GIF, as well as MP3 (meant to contain audio descriptions for pictorial logotypes). This tool checks that input files are valid in their respective formats, but does not perform strict constraints checking (e.g. it checks for the lack of `<script>` elements in an SVG and canonicalizes it, but does not validate it as *SVG Tiny 1.2* as per RFC). However, **it is up to the users' sole responsibility** to ensure the files comply with the technical format constrains from [RFC 9399](https://www.rfc-editor.org/rfc/rfc9399) and, above all, that they do not contain **malware**.

This Python script includes a class to manipulate Object Identifiers (OIDs), plus classes to prepare the logos embedding within X.509 certificates. The script's deliverable is multi-section, OpenSSL configuration file template that can be used by OpenSSL itself to embed commandline-input logotypes into newly generated digital certificates relying on that template.
