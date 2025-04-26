package routes

import (
	"errors"
	"fmt"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"
	"strings"

	"github.com/lescuer97/nutmix/api/cashu"
)

func ConvertUnitToSigUnit(unit string) *sig.CurrencyUnit {

	currUnit := sig.CurrencyUnit{}

	switch strings.ToLower(unit) {
	case "sat":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_SAT}
	case "msat":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_MSAT}
	case "usd":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_USD}
	case "eur":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_EUR}
	case "auth":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_AUTH}
	default:
		currUnit.CurrencyUnit = &sig.CurrencyUnit_CustomUnit{CustomUnit: strings.ToLower(unit)}
	}

	return &currUnit
}

func ConvertToKeysResponse(pubkey []byte, keys []signer.MintPublicKeyset) *sig.KeysResponse {
	response := sig.KeysResponse{}

	responseResult := sig.KeysResponse_Keysets{
		Keysets: &sig.SignatoryKeysets{
			Keysets: make([]*sig.KeySet, len(keys)),
		},
	}
	responseResult.Keysets.Pubkey = pubkey
	for i, mintPubKey := range keys {
		keys := sig.Keys{
			Keys: mintPubKey.Keys,
		}
		currUnit := ConvertUnitToSigUnit(mintPubKey.Unit)
		keyset := sig.KeySet{
			Id:          mintPubKey.Id,
			Unit:        currUnit,
			Active:      mintPubKey.Active,
			InputFeePpk: uint64(mintPubKey.InputFeePpk),
			Keys:        &keys,
		}
		responseResult.Keysets.Keysets[i] = &keyset
	}

	response.Result = &responseResult
	return &response
}
func ConvertToKeyRotationResponse(key signer.MintPublicKeyset) *sig.KeyRotationResponse {
	response := sig.KeyRotationResponse{}

	keys := sig.Keys{
		Keys: key.Keys,
	}
	currUnit := ConvertUnitToSigUnit(key.Unit)
	keyset := sig.KeySet{
		Id:          key.Id,
		Unit:        currUnit,
		Active:      key.Active,
		InputFeePpk: uint64(key.InputFeePpk),
		Keys:        &keys,
	}
	responseResult := sig.KeyRotationResponse_Keyset{
		Keyset: &keyset,
	}

	response.Result = &responseResult
	return &response
}

type RotationRequest struct {
	Fee      uint64
	Unit     cashu.Unit
	MaxOrder uint64
}

func ConvertSigRotationRequest(req *sig.RotationRequest) (RotationRequest, error) {
	rotationRequest := RotationRequest{}

	if req == nil {
		return rotationRequest, fmt.Errorf("No rotation request available")
	}
	rotationRequest.Fee = req.InputFeePpk
	rotationRequest.MaxOrder = req.MaxOrder

	unit, err := ConvertSigUnitToCashuUnit(req.Unit)
	if err != nil {
		return rotationRequest, fmt.Errorf("ConvertSigUnitToCashuUnit(req.Unit). %w", err)

	}
	rotationRequest.Unit = unit

	return rotationRequest, nil
}

func ConvertSigUnitToCashuUnit(sigUnit *sig.CurrencyUnit) (cashu.Unit, error) {
	switch sigUnit.GetUnit().Number() {
	case sig.CurrencyUnitType_SAT.Enum().Number():
		return cashu.Sat, nil
	case sig.CurrencyUnitType_MSAT.Enum().Number():
		return cashu.Msat, nil
	case sig.CurrencyUnitType_EUR.Enum().Number():
		return cashu.EUR, nil
	case sig.CurrencyUnitType_USD.Enum().Number():
		return cashu.USD, nil
	case sig.CurrencyUnitType_AUTH.Enum().Number():
		return cashu.AUTH, nil

	default:
		unit, err := cashu.UnitFromString(strings.ToLower(sigUnit.GetCustomUnit()))

		if err != nil {
			return cashu.Sat, fmt.Errorf("cashu.UnitFromString(strings.ToLower(req.Unit.String())). %w", err)
		}
		return unit, nil

	}

}

func ConvertErrorToResponse(err error) *sig.Error {
	// If error is nil, return nil to maintain the same behavior as mapErrorToGrpcError
	if err == nil {
		return nil
	}

	// Create error response
	error := sig.Error{}

	switch {
	case errors.Is(err, cashu.UsingInactiveKeyset):
		error.Code = sig.ErrorCode_KEYSET_INACTIVE
		error.Detail = "Using an inactive keyset"
	case errors.Is(err, cashu.ErrInvalidBlindMessage):
		error.Code = sig.ErrorCode_INVALID_BLIND_MESSAGE
		error.Detail = "Invalid blind message"
	case errors.Is(err, cashu.ErrCouldNotParseUnitString):
		error.Code = sig.ErrorCode_UNIT_NOT_SUPPORTED
		error.Detail = "Unit not supported"
	case errors.Is(err, cashu.ErrKeysetForProofNotFound):
		error.Code = sig.ErrorCode_KEYSET_NOT_KNOWN
		error.Detail = "Keyset does not exist"
	case errors.Is(err, cashu.ErrInvalidProof):
		error.Code = sig.ErrorCode_INVALID_PROOF
		error.Detail = "Invalid proof"
	default:
		error.Code = sig.ErrorCode_UNKNOWN
		error.Detail = err.Error()
	}

	return &error
}
