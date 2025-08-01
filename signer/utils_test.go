package signer

import (
	"encoding/binary"
	"encoding/hex"
	"nutmix_remote_signer/database"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/lescuer97/nutmix/api/cashu"
)

func TestConvertionOfBytesToInt(t *testing.T) {
	hexStr := "339efeab"
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("hex.DecodeString(hexStr). %v", err)
	}
	number := binary.BigEndian.Uint32(bytes)

	if number != 866057899 {
		t.Errorf("Bytes where wrongly encoded")
	}
}

// Test Vectors Remote signer
func TestSatConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.Sat)

	if intRef != 866057899 {
		t.Errorf("sat bytes are wrong")
	}
}

// Test Vectors Remote signer
func TestMSatConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.Msat)

	if intRef != 4128155635 {
		t.Errorf("sat bytes are wrong")
	}
}

// Test Vectors Remote signer
func TestEurConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.EUR)

	if intRef != 3122566600 {
		t.Errorf("Eur bytes are wrong")
	}
}
func TestUsdConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.USD)

	if intRef != 3591355783 {
		t.Errorf("USD bytes are wrong")
	}
}

func TestAuthConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.AUTH)

	if intRef != 3186924604 {
		t.Errorf("auth bytes are wrong")
	}
}

func TestDeriveKeysetSat(t *testing.T) {
	seed := database.Seed{
		Active:      true,
		CreatedAt:   time.Now().Unix(),
		Version:     1,
		Unit:        cashu.Sat.String(),
		Id:          "",
		InputFeePpk: 0,
		Legacy:      false,
		Amounts:     GetAmountsFromMaxOrder(DefaultMaxOrder),
	}
	privateKeyBytes, err := hex.DecodeString(MintPrivateKey)
	if err != nil {
		t.Fatalf("Could not parse privakey from bytes")
		return
	}

	masterKey, err := hdkeychain.NewMaster(privateKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("could not setup master key")
		return
	}

	mintKeyset, err := DeriveKeyset(masterKey, seed, seed.Amounts)
	if err != nil {
		t.Errorf("could not derive keysets %v", err)
		return
	}

	keysResult := map[string]string{
		"1":                   "021164fe527a138a0b8faabfec069624b82f950b643131c88fcc8aa1dea314aa23",
		"2":                   "02665d26e298d92c7e5be4b90dfa1ce4f8ab994a2b40fe8ae4da928e429b08f192",
		"4":                   "03aa8bc81753616bacb33cf3045d8e260c2c126bb830c9f3ccd92be22fe0c5c2d3",
		"8":                   "0271547233042916ddc003719e10c69a40798646a31119ad9fcf4fbeed53e0bf8d",
		"16":                  "029998f61894f1686c72338447aad85851fffc8e00849d086a6eb88624fb08e68d",
		"32":                  "0363b5b065311bf9575fc3dbb6000349feb6905fd973f17b38423db5c6917571b8",
		"64":                  "03ca10cc7707c7e4042a8fedaefcee4d9814bd7b2da8117f6c35a1aa7d37764334",
		"128":                 "037535b1d12bbe750960c4deca8befa52aba2aaadd85e1ca6c6b6c012f95956bfa",
		"256":                 "026ec044151003bbb8bc38282316d8d52cfada31e4e886ddf170e8bb33fb98130e",
		"512":                 "038b55670da32e38f791d1e5eb0bb6ec687d09e71bad1289848c104ca85820646f",
		"1024":                "026c3b74a04837c617cacbc6f10d78dde6e4a24c505be497c73fafc31e833051f1",
		"2048":                "037c90e4ec51ec18dcf148eaee86a114d9d861b07ca6e63d762b0cffa845c920a4",
		"4096":                "025bce987f3e5a87bb164f6a99849b2f5c1a167a6933ac4f5458ae3e757fd1e6b0",
		"8192":                "028c3e2d436ab02a58e3c1eef5bc9ba5e49b528158c7c180b46dc140d3ab0dafbb",
		"16384":               "02196b2138b196b7704c98adc65bb64e024369b7382eb1e1e1bcceee6d6df88946",
		"32768":               "03f0b6b2651d2de5ecf00d75d1312e66a5a3d8af2293e326763b56dbff0fb48890",
		"65536":               "020d6fc6c36c66c4b52d3da8dc9ff6ccc89248cd46ce3df3b7c764bb6050068fd5",
		"131072":              "02b0932b4d6265ee65c0ad2a3e718049a6988715ac57bdc120e05de2e73051f341",
		"262144":              "02ec8680fa0c2e0da8caa8a12f84f7a713d718df37766bd9be8818902ef558279c",
		"524288":              "03ef6b9000f3af84f793a2e3ffffc1ec468db83cbed39afb6104f26666bd09bf06",
		"1048576":             "03e9ed4e1bf605a6de185acc597007c821bdeae0ad5f13b422bba9909ddd62aa7b",
		"2097152":             "0327a5c1802632f6bdeef8849ebcef00a2c8fa4fb19830183ac755d0d3008a68f6",
		"4194304":             "035fc46509cb02bad99f7daf0541db0b803efc8752390349a34c12ad2d3a46a3c3",
		"8388608":             "024583a5efb09f020469a0027529e57db69b1f4c889125613d85fd2115a891766c",
		"16777216":            "03ced8e554cde58f4ce459c9d9944b94a76c2bf6f9ba3a9a1a1ed683d2484314fe",
		"33554432":            "0368f6307dca4295872306af22c8a185e97d3eca65e1caeb3ffe40c240347942bc",
		"67108864":            "0289da1bd9353f4bbb2f84feebd4d66edb42fb74dae57d5ac21d181ffa371810c3",
		"134217728":           "0300b187928533dfead48e8f1fd54baac6f817f64db191c30ca1c83668fe6b66a7",
		"268435456":           "027877c33d246da09ab5ef2c2b3bf666569d7e2fb7041bce045865b478010c6dbe",
		"536870912":           "030a01640da00e636edd999ec5a5fb0159f8b79373b8e02866ebd9e9a8bf50f441",
		"1073741824":          "02f1201024c29be9a1f18db260a21736f30a81faf136a17977ce693913171bbad1",
		"2147483648":          "03ac9b95c22c351a4af76a13ba30f85767e7924ffeca0131437c3091a5edd57574",
		"4294967296":          "028977b82af3e5543505ca839cb88ca70cb8bd69faeed898687dbf222416e566d0",
		"8589934592":          "02c2ebb25412c731916ad62a25ce25696edd12833e1c2e4d168e6e33c02e53adc7",
		"17179869184":         "03ce6d04f870305cd649bf34171a942ecaa9ce87761a0de971801f7e81511307e4",
		"34359738368":         "02c311ddee28b2a2008ab0325015206231503ce1eae88ce8b7fb7c32a3611c8680",
		"68719476736":         "02342f2559c343960d6fda0ad29cccd0847b32274979d468d2e53152e3efef28e9",
		"137438953472":        "032d57b57294f78274d68fec82f6d1b3193d23a481e97545fddb6ac3eb64f02034",
		"274877906944":        "03c4f239df977e390d896e6499052e79d45c153b11ad9c34dfbb24713ead535500",
		"549755813888":        "02264957378031c39e181b7c9d54e28cc08c227c40a0cbb2d3d681d97eed2a2d04",
		"1099511627776":       "033e31bc900be54c9506cdc0a944d48d0998493f9307fd70977a0f52c9653f0248",
		"2199023255552":       "03bcfee44f1fbf251279c50cff59c6ea695466ab50c48d071da88f79afb43ad2d0",
		"4398046511104":       "031dee406e1bb31d15601a425911410d9ca80c010939473597496e116f8551057a",
		"8796093022208":       "0382c20673e51c8e1c07c884cb60a9cf056476c7e06e7a39acadaaa6f700bc76ad",
		"17592186044416":      "03d2bea910c0306909fa02c7a958b1421fc9423f8470287c1a68a97b7b510e62fb",
		"35184372088832":      "03c192a71dd08ef2add45479488486777bc5833f7a8fbade66f9463c0f64b7a38f",
		"70368744177664":      "026b69aa2daaaef42c9f7ecb8bcfa408c955c9a381061c4c3885743a17dd1e25c3",
		"140737488355328":     "032a82c7364a3a559019ccae222bda2a83e8c2b215a95249a73a3054a7ec3531fd",
		"281474976710656":     "03a1a40c4c17e5efb82dfccc5db3967bdbda059546469fa3c16ba306b9128da09b",
		"562949953421312":     "03d8d2304560fe399a5bf896f3bf32c2ae6827f1a081e0c244374d1276245038a7",
		"1125899906842624":    "038df80016e3e2cbf566f6927e34026135f437a37635fbbc2ce15a3a0e09ee9cb0",
		"2251799813685248":    "02cc07205f0cdc8ae89bfc1e711bd6090e1053394afc3cd963801316656e0e3630",
		"4503599627370496":    "03385d967feaa1b73c25786159157dff220190f3a675000caf9bad781a696df9fb",
		"9007199254740992":    "032a7bccd7408e512ddc875d69214bba481f21c49afe6b5de5fbb440b40ef72258",
		"18014398509481984":   "0349aa9c24797e22c65980697697a87891c3f13a44f4167d44746f8c5a21b84d6d",
		"36028797018963968":   "02fc0d68852dec1aa376992aa2c94fc43e0c1d0331416822da884ee3310d566024",
		"72057594037927936":   "02eb707ea5906e64153085c202b693e183b4bd28bc2ddffe29b5de83bdabe12455",
		"144115188075855872":  "033587b551151db7a792e0188ebe06331e660eada2c6f9ae160b0842941463e528",
		"288230376151711744":  "0260fecf8dc279bec9d237451321c28b0dca5500471d0c41278676158c08d0ba4e",
		"576460752303423488":  "0272b0f3689e7d430418748c4b93cb26f14cfae08253f4b0f2b8ae60cc437488e0",
		"1152921504606846976": "0234ecb164cf8b6140a80c6db09c727bbacfbd7f4036e674a9c30d082016fffd8c",
		"2305843009213693952": "02dd6dd685be4f3dda8f160c958fd902f92a192990692d52782d6f7d7fe6222e6c",
		"4611686018427387904": "028b6196ff10965461ac65a75fc9eebe088528b057610e598b1dad63fc0e1ca4e9",
		"9223372036854775808": "02dffebbe5d39101efd34332a7f359aff03bca367d867a53fac517a4776dbb5c36",
	}

	for key := range mintKeyset.Keys {
		keys := mintKeyset.Keys[key]
		val, ok := keysResult[strconv.FormatUint(key, 10)]
		if !ok {
			t.Fatalf("There should always be key for value")
		}
		if hex.EncodeToString(keys.PublicKey.SerializeCompressed()) != val {
			t.Errorf("key values should be the same: \n CalculatedKey %x. \n NeededKey %v", keys.PublicKey.SerializeCompressed(), val)
		}
	}
}

func TestDeriveKeysetAuth(t *testing.T) {
	seed := database.Seed{
		Active:      true,
		CreatedAt:   time.Now().Unix(),
		Version:     1,
		Unit:        cashu.AUTH.String(),
		Id:          "",
		InputFeePpk: 0,
		Legacy:      false,
		Amounts:     GetAmountsFromMaxOrder(DefaultMaxOrder),
	}
	privateKeyBytes, err := hex.DecodeString(MintPrivateKey)
	if err != nil {
		t.Fatalf("Could not parse privakey from bytes")
		return
	}

	masterKey, err := hdkeychain.NewMaster(privateKeyBytes, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("could not setup master key")
		return
	}

	mintKeyset, err := DeriveKeyset(masterKey, seed, seed.Amounts)
	if err != nil {
		t.Errorf("could not derive keysets %v", err)
		return
	}

	keysResult := map[string]string{
		"1": "02e18e9970c71607bcb5b41d4aac4cc007df236a15ed22ca0a8c2a26eb6f78ba96",
	}
	for key := range mintKeyset.Keys {
		keys := mintKeyset.Keys[key]
		val, ok := keysResult[strconv.FormatUint(key, 10)]
		if !ok {
			t.Fatalf("There should always be key for value")
		}
		if hex.EncodeToString(keys.PublicKey.SerializeCompressed()) != val {
			t.Errorf("key values should be the same: \n CalculatedKey %x. \n NeededKey %v", keys.PublicKey.SerializeCompressed(), val)
		}
	}
}
