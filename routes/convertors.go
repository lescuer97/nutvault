package routes

import (
	"errors"
	"fmt"
	"log"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"
	"nutmix_remote_signer/utils"
	"strings"

	"github.com/lescuer97/nutmix/api/cashu"
)

func ConvertUnitToSigUnit(unit string) *sig.CurrencyUnit {

	currUnit := sig.CurrencyUnit{}

	switch strings.ToLower(unit) {
	case "sat":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_SAT}
	case "msat":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_MSAT}
	case "usd":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_USD}
	case "eur":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_EUR}
	case "auth":
		currUnit.CurrencyUnit = &sig.CurrencyUnit_Unit{Unit: sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_AUTH}
	default:
		currUnit.CurrencyUnit = &sig.CurrencyUnit_CustomUnit{CustomUnit: strings.ToLower(unit)}
	}

	return &currUnit
}

func ConvertToKeysResponse(pubkey []byte, keys []signer.MintPublicKeyset) *sig.KeysResponse {
	response := sig.KeysResponse{
		Keysets: &sig.SignatoryKeysets{
			Keysets: make([]*sig.KeySet, len(keys)),
		},
	}

	response.Keysets.Pubkey = pubkey
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
			Version:     mintPubKey.Version,
		}

		if keyset.Keys == nil {
			log.Panicf("Keys should always be set should always be set")
		}
		if keyset.Id == nil {
			log.Panicf("Id should always be set")
		}

		response.Keysets.Keysets[i] = &keyset
	}

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
		Version:     key.Version,
	}

	if keyset.Keys == nil {
		log.Panicf("Keys should always be set should always be set")
	}
	if keyset.Id == nil {
		log.Panicf("Id should always be set")
	}
	response.Keyset = &keyset

	return &response
}

type RotationRequest struct {
	Fee     uint64
	Unit    cashu.Unit
	Amounts []uint64
}

func ConvertSigRotationRequest(req *sig.RotationRequest) (RotationRequest, error) {
	rotationRequest := RotationRequest{}

	if req == nil {
		return rotationRequest, fmt.Errorf("No rotation request available")
	}
	rotationRequest.Fee = req.InputFeePpk
	rotationRequest.Amounts = req.Amounts

	unit, err := ConvertSigUnitToCashuUnit(req.Unit)
	if err != nil {
		return rotationRequest, fmt.Errorf("ConvertSigUnitToCashuUnit(req.Unit). %w", err)

	}
	rotationRequest.Unit = unit

	return rotationRequest, nil
}

func ConvertSigUnitToCashuUnit(sigUnit *sig.CurrencyUnit) (cashu.Unit, error) {
	switch sigUnit.GetUnit().Number() {
	case sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_SAT.Enum().Number():
		return cashu.Sat, nil
	case sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_MSAT.Enum().Number():
		return cashu.Msat, nil
	case sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_EUR.Enum().Number():
		return cashu.EUR, nil
	case sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_USD.Enum().Number():
		return cashu.USD, nil
	case sig.CurrencyUnitType_CURRENCY_UNIT_TYPE_AUTH.Enum().Number():
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
		error.Code = sig.ErrorCode_ERROR_CODE_KEYSET_INACTIVE
		error.Detail = "Using an inactive keyset"
	case errors.Is(err, cashu.ErrInvalidBlindMessage):
		error.Code = sig.ErrorCode_ERROR_CODE_INVALID_BLIND_MESSAGE
		error.Detail = "Invalid blind message"
	case errors.Is(err, cashu.ErrCouldNotParseUnitString):
		error.Code = sig.ErrorCode_ERROR_CODE_UNIT_NOT_SUPPORTED
		error.Detail = "Unit not supported"
	case errors.Is(err, cashu.ErrKeysetForProofNotFound):
		error.Code = sig.ErrorCode_ERROR_CODE_KEYSET_NOT_KNOWN
		error.Detail = "Keyset does not exist"
	case errors.Is(err, cashu.ErrInvalidProof):
		error.Code = sig.ErrorCode_ERROR_CODE_INVALID_PROOF
		error.Detail = "Invalid proof"
	case errors.Is(err, utils.ErrAboveMaxOrder):
		error.Code = sig.ErrorCode_ERROR_CODE_COULD_NOT_ROTATE_KEYSET
		error.Detail = "The max order was above the limit"
	default:
		error.Code = sig.ErrorCode_ERROR_CODE_UNSPECIFIED
		error.Detail = err.Error()
	}

	return &error
}
