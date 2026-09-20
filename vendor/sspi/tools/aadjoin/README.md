
# AADJoin

### Purpose of this tool

This tool simulates new device joining to the Azure Active Directory and device certificates obtaining.

It can obtain three types of certificates:

* the device certificate;
* the client certificate for the P2P authorization
* the server certificate for the P2P authorization

All generated keys, CSRs, and certificates will be saved in appropriate files. You will see paths to them in logs.

### How use it

```
AADJoin 1.0.0
Copyright (C) 2022 AADJoin

  -j, --join-new-device     Join new device to the Azure AD

  -c, --client-p2p-cert     Obtain P2P certificate for the client authorization

  -s, --server-p2p-cert     Obtain P2P certificate for the server authorization

  -d, --domain              Required. Azure AD domain

  -u, --username            Required. User Azure AD username in FQDN format

  -p, --password            Required. User password

  -e, --existing-device     Path to the PFX file with the device key + certificate

  -f, --pfx-key-password    PFX file password

  --help                    Display this help screen.

  --version                 Display version information.
```

*Attention: To run this tool you need .Net 6.0.8 runtime*

### Example

Create and join a new device to the AzureAD:

```bash
AADJoin.exe --join-new-device --domain dataans.com --username s10@dataans.com --password wwwWWW222@@@
```

The comman above will create a three files:

* `<device id>.key` - the device private key;
* `<random guid>.csr` - the certificate request that had been used for the device certificate generation;
* `<device id>.cer` - the device certificate;

My example:

```
03b8620d-12ff-48ee-b036-e1cf4c598609.key
007bfc57-2504-404c-99f4-6160d1bfe2cb.csr
03b8620d-12ff-48ee-b036-e1cf4c598609.cer
```

We can obtain the server P2P sertificate with the following command:

```bash
AADJoin.exe --existing-device 03b8620d-12ff-48ee-b036-e1cf4c598609.pfx --pfx-key-password 03b8620d-12ff-48ee-b036-e1cf4c598609 --domain dataans.com --username s10@dataans.com --password wwwWWW222@@@ --server-p2p-cert
```

The command above will create two files:

* `<device id>_server_auth_p2p.cer` - the P2P certificate for the server authentication;
* `<device id>_server_auth_p2p_ca.cer` - the P2P CA certificate of the obtained certificate;

We can obtain the client P2P sertificate with the following command:

```bash
AADJoin.exe --existing-device 03b8620d-12ff-48ee-b036-e1cf4c598609.pfx --pfx-key-password 03b8620d-12ff-48ee-b036-e1cf4c598609 --domain dataans.com --username s10@dataans.com --password wwwWWW222@@@ --client-p2p-cert
```

The command above will create two files:

* `<device id>_client_auth_p2p.cer` - the P2P certificate for the client authentication;
* `<device id>_client_auth_p2p_ca.cer` - the P2P CA certificate of the obtained certificate;

And here are files I had:

```
03b8620d-12ff-48ee-b036-e1cf4c598609_client_auth_p2p.cer
03b8620d-12ff-48ee-b036-e1cf4c598609_client_auth_p2p_ca.cer
03b8620d-12ff-48ee-b036-e1cf4c598609_server_auth_p2p.cer
03b8620d-12ff-48ee-b036-e1cf4c598609_server_auth_p2p_ca.cer
```
