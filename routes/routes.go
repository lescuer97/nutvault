package routes

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"

	goNutsCashu "github.com/elnosh/gonuts/cashu"
	"github.com/elnosh/gonuts/cashu/nuts/nut11"
	"github.com/elnosh/gonuts/cashu/nuts/nut14"
	"github.com/lescuer97/nutmix/api/cashu"
)

type Server struct {
	Signer signer.Signer
	sig.SignerServiceServer
}

func (s *Server) BlindSign(ctx context.Context, message *sig.BlindedMessages) (*sig.BlindSignResponse, error) {
	slog.Info("Receive requequest for Blind signing")

	blindMessages := goNutsCashu.BlindedMessages{}
	for _, val := range message.BlindedMessages {
		blindMessages = append(blindMessages, goNutsCashu.BlindedMessage{Amount: val.Amount, Id: val.KeysetId, B_: hex.EncodeToString(val.BlindedSecret)})
	}

	blindSigs, err := s.Signer.SignBlindMessages(blindMessages)

	blindSigsResponse := sig.BlindSignResponse{}
	if err != nil {
		slog.Error(err.Error())
		return &blindSigsResponse, fmt.Errorf("s.signer.GetActiveKeys(). %w", err)
	}

	blindSignatures := sig.BlindSignatures{
		BlindSignatures: []*sig.BlindSignature{},
	}
	blindSigsResult := sig.BlindSignResponse_Sigs{
		Sigs: &blindSignatures,
	}
	for _, val := range blindSigs {
		blindSec, err := hex.DecodeString(val.C_)
		if err != nil {
			slog.Error("Could not decode blindSignature ", slog.String("extra", err.Error()))
			return &blindSigsResponse, fmt.Errorf("hex.DecodeString(val.C_). %w", err)
		}
		slog.Debug("Trying to decode dleq from signer")
		EBytes, err := hex.DecodeString(val.DLEQ.E)
		if err != nil {
			err = fmt.Errorf("hex.DecodeString(val.DLEQ.E)): %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, err
		}

		SBytes, err := hex.DecodeString(val.DLEQ.S)
		if err != nil {
			err = fmt.Errorf("hex.DecodeString(val.DLEQ.S)): %w %w", cashu.ErrInvalidBlindMessage, err)
			return nil, err
		}
		dleq := sig.BlindSignatureDLEQ{
			E: EBytes,
			S: SBytes,
		}

		blindSigsResult.Sigs.BlindSignatures = append(blindSigsResult.Sigs.BlindSignatures, &sig.BlindSignature{Amount: val.Amount, KeysetId: val.Id, BlindedSecret: blindSec, Dleq: &dleq})

	}

	blindSigsResponse.Result = &blindSigsResult
	return &blindSigsResponse, nil
}

func (s *Server) VerifyProofs(ctx context.Context, proofs *sig.Proofs) (*sig.BooleanResponse, error) {
	slog.Info("Receive Proof verification request")
	cashuProofs := goNutsCashu.Proofs{}
	slog.Debug("Parsing grpc proofs to signer types")
	for _, val := range proofs.Proof {
		htlcWitness := val.Witness.GetHtlcWitness()
		p2pkWitness := val.Witness.GetP2PkWitness()
		var witness string = ""

		if p2pkWitness != nil {
			wit := nut11.P2PKWitness{
				Signatures: p2pkWitness.Signatures,
			}
			witnessBytes, err := json.Marshal(wit)
			if err != nil {
				slog.Error("could not marshall p2pk witness", slog.String("extra", err.Error()))
				return nil, fmt.Errorf("s.Signer.VerifyProofs(cashuProofs, []cashu.BlindedMessage{}). %w", err)
			}
			witness = string(witnessBytes)
		} else if htlcWitness != nil {
			wit := nut14.HTLCWitness{
				Signatures: htlcWitness.Signatures,
				Preimage:   htlcWitness.Preimage,
			}
			witnessBytes, err := json.Marshal(wit)
			if err != nil {
				slog.Error(err.Error())
				return nil, fmt.Errorf("s.Signer.VerifyProofs(cashuProofs, []cashu.BlindedMessage{}). %w", err)
			}
			witness = string(witnessBytes)
		}

		cashuProofs = append(cashuProofs, goNutsCashu.Proof{Amount: val.Amount, Id: val.KeysetId, C: hex.EncodeToString(val.C), Witness: witness, Secret: string(val.Secret)})
	}
	err := s.Signer.VerifyProofs(cashuProofs, goNutsCashu.BlindedMessages{})

	boolResponse := sig.BooleanResponse{}
	if err != nil {
		slog.Error("Could not verify Proofs", slog.String("extra", err.Error()))
		boolResponse.Result = &sig.BooleanResponse_Error{
			Error: &sig.Error{
				Code:   sig.ErrorCode_UNKNOWN,
				Detail: "I don't know this",
			},
		}
		return &boolResponse, nil
	}

	boolResponse.Result = &sig.BooleanResponse_Success{
		Success: true,
	}
	return &boolResponse, nil
}

func (s *Server) Keysets(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysResponse, error) {
	slog.Debug("Received request to all keysets")

	keys := s.Signer.GetKeysets()
	pubkey := s.Signer.GetSignerPubkey()

	keysResponse := ConvertToKeysResponse(pubkey, keys)
	return keysResponse, nil
}

func (s *Server) RotateKeyset(ctx context.Context, req *sig.RotationRequest) (*sig.KeyRotationResponse, error) {
	slog.Info("Received key rotation request")

	rotationReq, err := ConvertSigRotationRequest(req)
	if err != nil {
		slog.Error("Could not convert the rotation request", slog.String("extra", err.Error()))
		return nil, fmt.Errorf("s.Signer.RotateKeyset(). %w", err)
	}

	newKey, err := s.Signer.RotateKeyset(rotationReq.Unit, rotationReq.Fee, rotationReq.MaxOrder)
	if err != nil {
		slog.Error("Could not rotate keysets", slog.String("extra", err.Error()))
		return nil, fmt.Errorf("s.Signer.RotateKeyset(). %w", err)
	}
	rotationResponse := ConvertToKeyRotationResponse(newKey)
	return rotationResponse, nil
}
