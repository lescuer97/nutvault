package routes

import (
	"context"
	"fmt"
	sig "nutmix_remote_signer/gen"
	"nutmix_remote_signer/signer"
)

type Server struct {
	Signer signer.Signer
	sig.SignerServer
}

func (s *Server) BlindSign(ctx context.Context, message *sig.BlindedMessages) (*sig.BlindSignatures, error) {

	return nil, nil
}

func (s *Server) VerifyProofs(ctx context.Context, proofs *sig.Proofs) (*sig.Success, error) {

	return nil, nil
}
func (s *Server) Keys(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysResponse, error) {
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

func (s *Server) Keyset(ctx context.Context, _ *sig.EmptyRequest) (*sig.KeysetResponse, error) {

	keys, err := s.Signer.GetKeys()
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
