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

To run the signer do:
```bash
just dev
```

If you want to run the web UI as well, set `ENABLE_WEB_UI=true` and optionally set `WEB_UI_ADDR`.
The UI uses Nostr login in the browser and provisions per-account client certificates for gRPC mTLS.

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

If you enable the web UI for account creation, you also need a CA private key for issuing client certificates:
- ca-key.pem

Optional environment overrides:
- `TLS_SERVER_CERT_PATH`
- `TLS_SERVER_KEY_PATH`
- `TLS_CA_CERT_PATH`
- `TLS_CA_KEY_PATH`
- `ACCOUNT_TLS_DIR`

## UI development

Templ templates are used for the web UI.

Generate template code with:
```bash
just templ
```

`just build` and `just dev` already run template generation alongside protobuf generation.

