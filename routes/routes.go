package routes

import (
	"context"
	"encoding/hex"
	"time"

	"fmt"
	"log/slog"
	sig "nutmix_remote_signer/gen/signer"
	"nutmix_remote_signer/signer"

	goNutsCashu "github.com/elnosh/gonuts/cashu"
	"github.com/lescuer97/nutmix/api/cashu"
)

type Server struct {
	Signer *signer.Signer
	sig.SignerServiceServer
}

func (s *Server) BlindSign(ctx context.Context, message *sig.BlindedMessages) (*sig.BlindSignResponse, error) {
	slog.Info("Receive request for Blind signing")
	signerIn := ctx.Value(signerInfoKey)
	signerInfo, ok := signerIn.(signer.SignerInfo)
	if !ok {
		slog.Error(fmt.Sprintf("no valid signer came in. %+v", signerIn))
		errorResponse := sig.BlindSignResponse{}
		errorResponse.Error = &sig.Error{
			Code:   sig.ErrorCode_ERROR_CODE_UNSPECIFIED,
			Detail: "no valid signer",
		}
		return &errorResponse, nil
	}

	blindMessages := goNutsCashu.BlindedMessages{}
	for _, val := range message.BlindedMessages {
		blindMessages = append(blindMessages, goNutsCashu.BlindedMessage{Amount: val.Amount, Id: hex.EncodeToString(val.KeysetId), B_: hex.EncodeToString(val.BlindedSecret)})
	}

	blindSigs, err := s.Signer.SignBlindMessages(blindMessages, signerInfo)

	blindSigsResponse := sig.BlindSignResponse{}
	if err != nil {
		slog.Error(err.Error())
		if mappedErr := ConvertErrorToResponse(err); mappedErr != nil {
			blindSigsResponse.Error = mappedErr
			return &blindSigsResponse, nil
		}
		return &blindSigsResponse, fmt.Errorf("s.signer.SignBlindMessages(). %w", err)
	}

	blindSignatures := sig.BlindSignatures{
		BlindSignatures: []*sig.BlindSignature{},
	}
	for _, val := range blindSigs {
		blindSec, err := hex.DecodeString(val.C_)
		if err != nil {
			slog.Error("Could not decode blindSignature ", slog.String("extra", err.Error()))
			if mappedErr := ConvertErrorToResponse(err); mappedErr != nil {
				blindSigsResponse.Error = mappedErr
				return &blindSigsResponse, nil
			}
			return &blindSigsResponse, fmt.Errorf("hex.DecodeString(val.C_). %w", err)
		}
		slog.Debug("Trying to decode dleq from signer")
		EBytes, err := hex.DecodeString(val.DLEQ.E)
		if err != nil {
			mappedErr := ConvertErrorToResponse(fmt.Errorf("hex.DecodeString(val.DLEQ.E)): %w %w", cashu.ErrInvalidBlindMessage, err))
			if mappedErr != nil {
				blindSigsResponse.Error = mappedErr
				return &blindSigsResponse, nil
			}
			return nil, err
		}

		SBytes, err := hex.DecodeString(val.DLEQ.S)
		if err != nil {
			mappedErr := ConvertErrorToResponse(fmt.Errorf("hex.DecodeString(val.DLEQ.S)): %w %w", cashu.ErrInvalidBlindMessage, err))
			if mappedErr != nil {
				blindSigsResponse.Error = mappedErr
				return &blindSigsResponse, nil
			}
			return nil, err
		}
		dleq := sig.BlindSignatureDLEQ{
			E: EBytes,
			S: SBytes,
		}

		id, err := hex.DecodeString(val.Id)
		if err != nil {
			return &blindSigsResponse, fmt.Errorf("hex.DecodeString(val.Id). %w", err)
		}

		blindSignatures.BlindSignatures = append(blindSignatures.BlindSignatures, &sig.BlindSignature{Amount: val.Amount, KeysetId: id, BlindedSecret: blindSec, Dleq: &dleq})
	}
	blindSigsResponse.Sigs = &blindSignatures

	return &blindSigsResponse, nil
}

func (s *Server) VerifyProofs(ctx context.Context, proofs *sig.Proofs) (*sig.BooleanResponse, error) {
	slog.Info("Receive Proof verification request")
	signerIn := ctx.Value(signerInfoKey)
	signerInfo, ok := signerIn.(signer.SignerInfo)
	if !ok {
		slog.Error(fmt.Sprintf("no valid signer came in. %+v", signerIn))
		errorResponse := sig.BooleanResponse{}
		errorResponse.Error = &sig.Error{
			Code:   sig.ErrorCode_ERROR_CODE_UNSPECIFIED,
			Detail: "no valid signer",
		}
		return &errorResponse, nil
	}

	cashuProofs := goNutsCashu.Proofs{}
	slog.Debug("Parsing grpc proofs to signer types")
	for _, val := range proofs.Proof {
		cashuProofs = append(cashuProofs, goNutsCashu.Proof{Amount: val.Amount, Id: hex.EncodeToString(val.KeysetId), C: hex.EncodeToString(val.C), Witness: "", Secret: string(val.Secret)})
	}

	err := s.Signer.VerifyProofs(signerInfo, cashuProofs, goNutsCashu.BlindedMessages{})

	boolResponse := sig.BooleanResponse{}
	if err != nil {
		slog.Error("Could not verify Proofs", slog.String("extra", err.Error()))
		if mappedErr := ConvertErrorToResponse(err); mappedErr != nil {
			boolResponse.Error = mappedErr
			return &boolResponse, nil
		}
		return &boolResponse, fmt.Errorf("s.Signer.VerifyProofs(). %w", err)
	}

	boolResponse.Success = true
	return &boolResponse, nil
}

func (s *Server) Keysets(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysResponse, error) {
	slog.Debug("Received request to all keysets")

	signerIn := ctx.Value(signerInfoKey)
	signerInfo, ok := signerIn.(signer.SignerInfo)
	if !ok {
		slog.Error(fmt.Sprintf("no valid signer came in. %+v", signerIn))
		errorResponse := sig.KeysResponse{}
		errorResponse.Error = &sig.Error{
			Code:   sig.ErrorCode_ERROR_CODE_UNSPECIFIED,
			Detail: "no valid signer",
		}
		return &errorResponse, nil
	}

	keys, _ := s.Signer.GetKeysets(signerInfo)

	pubkey, _ := s.Signer.GetSignerPubkey(signerInfo)
	keysResponse := ConvertToKeysResponse(pubkey, keys)

	return keysResponse, nil
}

func (s *Server) RotateKeyset(ctx context.Context, req *sig.RotationRequest) (*sig.KeyRotationResponse, error) {
	slog.Info("Received key rotation request")

	signerIn := ctx.Value(signerInfoKey)
	signerInfo, ok := signerIn.(signer.SignerInfo)
	if !ok {
		slog.Error(fmt.Sprintf("no valid signer came in. %+v", signerIn))
		errorResponse := sig.KeyRotationResponse{}
		errorResponse.Error = &sig.Error{
			Code:   sig.ErrorCode_ERROR_CODE_UNSPECIFIED,
			Detail: "no valid signer",
		}
		return &errorResponse, nil
	}

	rotationReq, err := ConvertSigRotationRequest(req)
	if err != nil {
		slog.Error("Could not convert the rotation request", slog.String("extra", err.Error()))
		if mappedErr := ConvertErrorToResponse(err); mappedErr != nil {
			rotationResponse := sig.KeyRotationResponse{}
			rotationResponse.Error = mappedErr
			return &rotationResponse, nil
		}
		return nil, fmt.Errorf("ConvertSigRotationRequest(). %w", err)
	}

	// Convert FinalExpiry unix timestamp to time.Time. If 0, use default of 270 hours and log a warning.
	var expiryTime time.Time
	if rotationReq.FinalExpiry == 0 {
		expiryTime = time.Now().Add(270 * time.Hour)
		slog.Warn("RotationRequest did not include final_expiry; using default of 270 hours")
	} else {
		expiryTime = time.Unix(int64(rotationReq.FinalExpiry), 0)
	}

	newKey, err := s.Signer.RotateKeyset(signerInfo, rotationReq.Unit, rotationReq.Fee, rotationReq.Amounts, expiryTime)
	if err != nil {
		slog.Error("Could not rotate keysets", slog.String("extra", err.Error()))
		if mappedErr := ConvertErrorToResponse(err); mappedErr != nil {
			rotationResponse := sig.KeyRotationResponse{}
			rotationResponse.Error = mappedErr
			return &rotationResponse, nil
		}
		return nil, fmt.Errorf("s.Signer.RotateKeyset(). %w", err)
	}
	rotationResponse := ConvertToKeyRotationResponse(newKey)
	return rotationResponse, nil
}
