package signer

import "github.com/elnosh/gonuts/crypto"

type MintPublicKeyset struct {
	Id                string
	Unit              string
	Active            bool
	DerivationPathIdx uint32
	Keys              map[uint64]string
	InputFeePpk       uint
}

func MakeMintPublickeys(mintKey crypto.MintKeyset) MintPublicKeyset {

	return MintPublicKeyset{
		Id:                mintKey.Id,
		Unit:              mintKey.Unit,
		Active:            mintKey.Active,
		DerivationPathIdx: mintKey.DerivationPathIdx,
		Keys:              mintKey.DerivePublic(),
		InputFeePpk:       uint(mintKey.DerivationPathIdx),
	}
}
