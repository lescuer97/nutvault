# NutVault

**Experimental**

### Running key generation for grpc.

Run this command at the base of the repo:
```bash
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional gen/signer/signer.proto
```

## Adding a seedphrase 
When you run the signer for the first time you will need to add your private key to the libsecret service. 
This should be a BIP-39 seedphrase.
```bash 
# NOTE: when you run this command you will get a prompt for password. This is where you paste the seedphrase.
secret-tool store --label="nutvault-seed" label nutvault-seed
```

To run the signer do:
```bash
go run ./...
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




## How to add a private key to libscret
Run the following command a write the seedphrase to the input:
```bash 
secret-tool store --label="nutvault-seed" label nutvault-seed
```


## Multi mint account management
### 
Run this command to get account management going:
```
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional gen/account_management/account_management.proto
```

