package routes

import (
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"
)

func ConvertKeysToSig(keys signer.GetKeysResponse) *sig.KeysResponse {
	sigs := sig.KeysResponse{
		Keysets: make([]*sig.Keys, len(keys.Keysets)),
	}

	for i, val := range keys.Keysets {
		sigs.Keysets[i] = &sig.Keys{Id: val.Id, Unit: val.Unit, Keys: val.Keys, InputFeePpk: uint32(val.InputFeePpk)}
	}

	return &sigs
}

func ConvertKeyssetToSig(keys signer.GetKeysetsResponse) *sig.KeysetResponse {
	sigs := sig.KeysetResponse{
		Keysets: make([]*sig.Keyset, len(keys.Keysets)),
	}

	for i, val := range keys.Keysets {
		sigs.Keysets[i] = &sig.Keyset{Id: val.Id, Unit: val.Unit, Active: val.Active, InputFeePpk: uint32(val.InputFeePpk)}
	}

	return &sigs
}
func ConvertPubkeyToSig(pubkey []byte) *sig.PublicKey {
	sigs := sig.PublicKey{
		Pubkey: make([]byte, len(pubkey)),
	}

	copy(sigs.Pubkey, pubkey)

	return &sigs
}
