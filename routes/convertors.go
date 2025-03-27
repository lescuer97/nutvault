package routes

import (
	sig "nutmix_remote_signer/gen"
	"strconv"

	"github.com/elnosh/gonuts/cashu/nuts/nut01"
	"github.com/elnosh/gonuts/cashu/nuts/nut02"
)

func ConvertKeysToSig(keys nut01.GetKeysResponse) *sig.KeysResponse {
	sigs := sig.KeysResponse{
		Keysets: make([]*sig.Keys, len(keys.Keysets)),
	}

	for i, val := range keys.Keysets {

		keyMap := make(map[string]string)

		for val, key := range val.Keys {
			keyMap[strconv.FormatUint(val, 10)] = key
		}

		sigs.Keysets[i] = &sig.Keys{Id: val.Id, Unit: val.Unit, Keys: keyMap}
	}

	return &sigs
}

func ConvertKeyssetToSig(keys nut02.GetKeysetsResponse) *sig.KeysetResponse {
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
