# NutVault

**Experimental**

### Running key generation for grpc.

Run this command at the base of the repo:
```bash
just proto
```

## Adding a seedphrase 
The signer now creates a seedphrase automatically. You can still set one manually if you want to control the value.
This should be a BIP-39 seedphrase.
```bash 
# Optional: when you run this command you will get a prompt for password. This is where you paste the seedphrase.
just seed
```

## Multi-account support

Multi-account handling currently lives in the [`multi_account_signer_2` branch](https://github.com/lescuer97/nutvault/tree/multi_account_signer_2).
If you want to work with or test that version, check out that branch instead of `main`.

To run the signer do:
```bash
just dev
```

## How the signer communicates
The signer communicates by default using a linux abstract socket. This allows the signer to run in a whole different
isolated user. 
if you want to expose the signer to the web so it can run in the over the network, you just need to the `NETWORK`  enviroment variable to "true".

### Secure communication 
The Signer secures communication with the mint using mTLS. This will require for you to create 3 files in a directory
called `tls`.  

The files should be called: 
- server-cert.pem 
- server-key.pem
- ca-cert.pem
