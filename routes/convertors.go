package routes

import (
	"errors"
	sig "nutmix_remote_signer/gen"
	"strconv"

	"github.com/elnosh/gonuts/cashu/nuts/nut01"
	"github.com/elnosh/gonuts/cashu/nuts/nut02"
	"github.com/lescuer97/nutmix/api/cashu"
)

func ConvertKeysToSig(keys nut01.GetKeysResponse) *sig.KeysList {
	sigs := sig.KeysList{
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

func ConvertKeyssetToSig(keys nut02.GetKeysetsResponse) *sig.KeySetList {
	sigs := sig.KeySetList{
		Keysets: make([]*sig.Keyset, len(keys.Keysets)),
	}

	for i, val := range keys.Keysets {
		sigs.Keysets[i] = &sig.Keyset{Id: val.Id, Unit: val.Unit, Active: val.Active, InputFeePpk: uint32(val.InputFeePpk)}
	}

	return &sigs
}
func ConvertValuesToConfig(pubkey []byte, mintLimit uint64) *sig.ConfigResponse {
	sigs := sig.ConfigResponse{
		Pubkey:        make([]byte, len(pubkey)),
		SigningLimits: mintLimit,
	}

	copy(sigs.Pubkey, pubkey)

	return &sigs
}
func ConvertErrorToResponse(err error) *sig.Error {
	error := sig.Error{}

	switch {
	case errors.Is(err, cashu.ErrInvalidBlindMessage):
		error.Code = sig.ErrorCode_INVALID_BLIND_MESSAGE
		error.Detail = "Invalid blind message"
	case errors.Is(err, cashu.ErrCouldNotParseUnitString):
		error.Code = sig.ErrorCode_UNIT_NOT_SUPPORTED
		error.Detail = "Unit not supported"
	case errors.Is(err, cashu.ErrKeysetForProofNotFound):
		error.Code = sig.ErrorCode_KEYSET_NOT_KNOWN
		error.Detail = "Keyset does not exists"
	case errors.Is(err, cashu.ErrInvalidProof):
		error.Code = sig.ErrorCode_INVALID_PROOF
		error.Detail = "Invalid proof"
	default:
		error.Code = sig.ErrorCode_UNKNOWN
		error.Detail = err.Error()

	}
	// switch error

	return &error
}
