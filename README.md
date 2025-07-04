# NutVault

**Experimental**

### Running key generation for grpc.

Run this command at the base of the repo:
```
protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative --experimental_allow_proto3_optional gen/signer.proto
```

The first time running the mint you might need to run the mint with the ENV variable, MINT_PRIVATE_KEY with the hex
private key for the signer. The signer will storage this key inside the secret service for use later.  

You SHOULD not run the signer with the MINT_PRIVATE_KEY after the first time. This will expose your private key
unnecesarily. 

To run the signer do:
```
go run ./...
```

## if you want to run the remote signer exposed to the network. you just need to the `NETWORK`  enviroment variable to "true"

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

