package routes

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"

	"github.com/lescuer97/nutmix/api/cashu"
)

type Server struct {
	Signer signer.Signer
	sig.SignerServer
}

func (s *Server) BlindSign(ctx context.Context, message *sig.BlindedMessages) (*sig.BlindSignatures, error) {
	blindMessages := []cashu.BlindedMessage{}
	for _, val := range message.BlindedMessages {
		blindMessages = append(blindMessages, cashu.BlindedMessage{Amount: val.Amount, Id: val.KeysetId, B_: hex.EncodeToString(val.BlindedSecret)})
	}

	blindSigs, _, err := s.Signer.SignBlindMessages(blindMessages)

	blindSigsResponse := sig.BlindSignatures{}
	if err != nil {
		return &blindSigsResponse, fmt.Errorf("s.signer.GetActiveKeys(). %w", err)
	}

	blindSigsResponse.BlindSignatures = []*sig.BlindSignature{}
	for _, val := range blindSigs {
		blindSec, err := hex.DecodeString(val.C_)
		if err != nil {
			return &blindSigsResponse, fmt.Errorf("hex.DecodeString(val.C_). %w", err)
		}

		dleq := sig.BlindSignatureDLEQ{
			E: val.Dleq.E.Serialize(),
			S: val.Dleq.S.Serialize(),
		}
		blindSigsResponse.BlindSignatures = append(blindSigsResponse.BlindSignatures, &sig.BlindSignature{Amount: val.Amount, KeysetId: val.Id, BlindedSecret: blindSec, Dleq: &dleq})

	}
	return &blindSigsResponse, nil
}

func (s *Server) VerifyProofs(ctx context.Context, proofs *sig.Proofs) (*sig.Success, error) {
	cashuProofs := cashu.Proofs{}
	for _, val := range proofs.Proof {
		cashuProofs = append(cashuProofs, cashu.Proof{Amount: val.Amount, Id: val.KeysetId, C: hex.EncodeToString(val.C), Witness: val.Witness.String(), Secret: string(val.Secret)})
	}
	log.Printf("\n proofs %+v", cashuProofs)
	err := s.Signer.VerifyProofs(cashuProofs, []cashu.BlindedMessage{})

	success := sig.Success{}
	if err != nil {
		success.Success = false
		return &success, fmt.Errorf("s.Signer.VerifyProofs(cashuProofs, []cashu.BlindedMessage{}). %w", err)
	}
	success.Success = true
	return &success, nil
}

func (s *Server) ActiveKeys(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysResponse, error) {
	keys, err := s.Signer.GetActiveKeys()
	if err != nil {
		return nil, fmt.Errorf("s.signer.GetActiveKeys(). %w", err)
	}

	return ConvertKeysToSig(keys), nil
}

func (s *Server) KeysById(ctx context.Context, id *sig.Id) (*sig.KeysResponse, error) {
	key, err := s.Signer.GetKeysById(id.GetId())

	if err != nil {
		return nil, fmt.Errorf("s.signer.GetKeysById(id.GetId()). %w", err)
	}

	return ConvertKeysToSig(key), nil
}

func (s *Server) Keysets(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysetResponse, error) {

	keys, err := s.Signer.GetKeysets()
	if err != nil {
		return nil, fmt.Errorf("s.signer.GetKeys(). %w", err)
	}

	return ConvertKeyssetToSig(keys), nil
}

func (s *Server) Pubkey(ctx context.Context, _ *sig.EmptyRequest) (*sig.PublicKey, error) {

	pubkey, err := s.Signer.GetSignerPubkey()
	if err != nil {
		return nil, fmt.Errorf("s.signer.GetSignerPubkey(). %w", err)
	}

	return ConvertPubkeyToSig(pubkey), nil
}
func (s *Server) RotateKeyset(ctx context.Context, req *sig.RotationRequest) (*sig.Success, error) {

	unit, err := cashu.UnitFromString(req.GetUnit())
	if err != nil {
		return nil, fmt.Errorf("s.signer.GetSignerPubkey(). %w", err)
	}

	err = s.Signer.RotateKeyset(unit, uint(req.GetFee()))

	success := sig.Success{}
	if err != nil {
		success.Success = false
		return &success, fmt.Errorf("s.Signer.RotateKeyset(). %w", err)
	}

	success.Success = true
	return &success, nil
}

// 	r.POST("/blind_sign", func(c *gin.Context) {
//
// 		var messages []cashu.BlindedMessage
// 		err := c.ShouldBindJSON(&messages)
// 		if err != nil {
// 			c.Error(fmt.Errorf("c.ShouldBindJSON(&messages). %w", err))
// 			c.JSON(400, "Malformed body request")
// 			return
// 		}
// 		_, recoverySig, err := signer.SignBlindMessages(messages)
// 		if err != nil {
// 			c.Error(fmt.Errorf("signer.GetKeys(). %w", err))
// 			c.JSON(500, "Server side error")
// 			return
// 		}
//
// 		c.JSON(200, recoverySig)
// 	})
// 	r.POST("/verify_proofs", func(c *gin.Context) {
// 		var proofs cashu.Proofs
// 		err := c.ShouldBindJSON(&proofs)
// 		if err != nil {
// 			c.Error(fmt.Errorf("c.ShouldBindJSON(&proofs). %w", err))
// 			c.JSON(400, "Malformed body request")
// 			return
// 		}
//
// 		keys, err := signer.GetKeys()
// 		if err != nil {
// 			c.Error(fmt.Errorf("signer.GetKeys(). %w", err))
// 			c.JSON(500, "Server side error")
// 			return
// 		}
//
// 		c.JSON(200, keys)
// 	})
//
