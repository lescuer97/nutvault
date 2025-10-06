package signer

import (
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"nutmix_remote_signer/database"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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

	mintKeyset, err := DeriveKeyset(masterKey, seed)
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

	mintKeyset, err := DeriveKeyset(masterKey, seed)
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

// V2 Generation keysets
func TestKeysetIdGenerationV2Vector1(t *testing.T) {
	keysStringMap := map[string]string{
		"1": "03a40f20667ed53513075dc51e715ff2046cad64eb68960632269ba7f0210e38bc",
		"2": "03fd4ce5a16b65576145949e6f99f445f8249fee17c606b688b504a849cdc452de",
		"4": "02648eccfa4c026960966276fa5a4cae46ce0fd432211a4f449bf84f13aa5f8303",
		"8": "02fdfd6796bfeac490cbee12f778f867f0a2c68f6508d17c649759ea0dc3547528",
	}
	keysMap := make(map[uint64]*secp256k1.PublicKey)

	for key, val := range keysStringMap {
		// Parse the key as big.Int then to uint64 (safe since JSON keys are ≤ 2^63)
		keyInt, ok := new(big.Int).SetString(key, 10)
		if !ok {
			t.Fatalf("invalid key: %s", key)
		}
		if !keyInt.IsUint64() {
			t.Fatalf("key too large for uint64: %s", key)
		}
		uKey := keyInt.Uint64()

		// Decode hex string to bytes
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("invalid hex for key %s: %v", key, err)
		}

		// Parse compressed secp256k1 public key
		pk, err := btcec.ParsePubKey(b)
		if err != nil {
			t.Fatalf("invalid pubkey for key %s: %v", key, err)
		}

		keysMap[uKey] = pk
	}

	pubkeyList := convertPubkeysMapToOrderArray(keysMap)

	finalExpiry := time.Unix(2059210353, 0)
	keysetId := DeriveKeysetIdV2(pubkeyList, cashu.Sat.String(), &finalExpiry)

	if keysetId != "01adc013fa9d85171586660abab27579888611659d357bc86bc09cb26eee8bc035" {
		t.Errorf("keyset id is not correct.")
	}
}

// V2 Generation keysets
func TestKeysetIdGenerationV2Vector2(t *testing.T) {
	keysStringMap := map[string]string{
		"1":                   "03ba786a2c0745f8c30e490288acd7a72dd53d65afd292ddefa326a4a3fa14c566",
		"2":                   "03361cd8bd1329fea797a6add1cf1990ffcf2270ceb9fc81eeee0e8e9c1bd0cdf5",
		"4":                   "036e378bcf78738ddf68859293c69778035740e41138ab183c94f8fee7572214c7",
		"8":                   "03909d73beaf28edfb283dbeb8da321afd40651e8902fcf5454ecc7d69788626c0",
		"16":                  "028a36f0e6638ea7466665fe174d958212723019ec08f9ce6898d897f88e68aa5d",
		"32":                  "03a97a40e146adee2687ac60c2ba2586a90f970de92a9d0e6cae5a4b9965f54612",
		"64":                  "03ce86f0c197aab181ddba0cfc5c5576e11dfd5164d9f3d4a3fc3ffbbf2e069664",
		"128":                 "0284f2c06d938a6f78794814c687560a0aabab19fe5e6f30ede38e113b132a3cb9",
		"256":                 "03b99f475b68e5b4c0ba809cdecaae64eade2d9787aa123206f91cd61f76c01459",
		"512":                 "03d4db82ea19a44d35274de51f78af0a710925fe7d9e03620b84e3e9976e3ac2eb",
		"1024":                "031fbd4ba801870871d46cf62228a1b748905ebc07d3b210daf48de229e683f2dc",
		"2048":                "0276cedb9a3b160db6a158ad4e468d2437f021293204b3cd4bf6247970d8aff54b",
		"4096":                "02fc6b89b403ee9eb8a7ed457cd3973638080d6e04ca8af7307c965c166b555ea2",
		"8192":                "0320265583e916d3a305f0d2687fcf2cd4e3cd03a16ea8261fda309c3ec5721e21",
		"16384":               "036e41de58fdff3cb1d8d713f48c63bc61fa3b3e1631495a444d178363c0d2ed50",
		"32768":               "0365438f613f19696264300b069d1dad93f0c60a37536b72a8ab7c7366a5ee6c04",
		"65536":               "02408426cfb6fc86341bac79624ba8708a4376b2d92debdf4134813f866eb57a8d",
		"131072":              "031063e9f11c94dc778c473e968966eac0e70b7145213fbaff5f7a007e71c65f41",
		"262144":              "02f2a3e808f9cd168ec71b7f328258d0c1dda250659c1aced14c7f5cf05aab4328",
		"524288":              "038ac10de9f1ff9395903bb73077e94dbf91e9ef98fd77d9a2debc5f74c575bc86",
		"1048576":             "0203eaee4db749b0fc7c49870d082024b2c31d889f9bc3b32473d4f1dfa3625788",
		"2097152":             "033cdb9d36e1e82ae652b7b6a08e0204569ec7ff9ebf85d80a02786dc7fe00b04c",
		"4194304":             "02c8b73f4e3a470ae05e5f2fe39984d41e9f6ae7be9f3b09c9ac31292e403ac512",
		"8388608":             "025bbe0cfce8a1f4fbd7f3a0d4a09cb6badd73ef61829dc827aa8a98c270bc25b0",
		"16777216":            "037eec3d1651a30a90182d9287a5c51386fe35d4a96839cf7969c6e2a03db1fc21",
		"33554432":            "03280576b81a04e6abd7197f305506476f5751356b7643988495ca5c3e14e5c262",
		"67108864":            "03268bfb05be1dbb33ab6e7e00e438373ca2c9b9abc018fdb452d0e1a0935e10d3",
		"134217728":           "02573b68784ceba9617bbcc7c9487836d296aa7c628c3199173a841e7a19798020",
		"268435456":           "0234076b6e70f7fbf755d2227ecc8d8169d662518ee3a1401f729e2a12ccb2b276",
		"536870912":           "03015bd88961e2a466a2163bd4248d1d2b42c7c58a157e594785e7eb34d880efc9",
		"1073741824":          "02c9b076d08f9020ebee49ac8ba2610b404d4e553a4f800150ceb539e9421aaeee",
		"2147483648":          "034d592f4c366afddc919a509600af81b489a03caf4f7517c2b3f4f2b558f9a41a",
		"4294967296":          "037c09ecb66da082981e4cbdb1ac65c0eb631fc75d85bed13efb2c6364148879b5",
		"8589934592":          "02b4ebb0dda3b9ad83b39e2e31024b777cc0ac205a96b9a6cfab3edea2912ed1b3",
		"17179869184":         "026cc4dacdced45e63f6e4f62edbc5779ccd802e7fabb82d5123db879b636176e9",
		"34359738368":         "02b2cee01b7d8e90180254459b8f09bbea9aad34c3a2fd98c85517ecfc9805af75",
		"68719476736":         "037a0c0d564540fc574b8bfa0253cca987b75466e44b295ed59f6f8bd41aace754",
		"137438953472":        "021df6585cae9b9ca431318a713fd73dbb76b3ef5667957e8633bca8aaa7214fb6",
		"274877906944":        "02b8f53dde126f8c85fa5bb6061c0be5aca90984ce9b902966941caf963648d53a",
		"549755813888":        "029cc8af2840d59f1d8761779b2496623c82c64be8e15f9ab577c657c6dd453785",
		"1099511627776":       "03e446fdb84fad492ff3a25fc1046fb9a93a5b262ebcd0151caa442ea28959a38a",
		"2199023255552":       "02d6b25bd4ab599dd0818c55f75702fde603c93f259222001246569018842d3258",
		"4398046511104":       "03397b522bb4e156ec3952d3f048e5a986c20a00718e5e52cd5718466bf494156a",
		"8796093022208":       "02d1fb9e78262b5d7d74028073075b80bb5ab281edcfc3191061962c1346340f1e",
		"17592186044416":      "030d3f2ad7a4ca115712ff7f140434f802b19a4c9b2dd1c76f3e8e80c05c6a9310",
		"35184372088832":      "03e325b691f292e1dfb151c3fb7cad440b225795583c32e24e10635a80e4221c06",
		"70368744177664":      "03bee8f64d88de3dee21d61f89efa32933da51152ddbd67466bef815e9f93f8fd1",
		"140737488355328":     "0327244c9019a4892e1f04ba3bf95fe43b327479e2d57c25979446cc508cd379ed",
		"281474976710656":     "02fb58522cd662f2f8b042f8161caae6e45de98283f74d4e99f19b0ea85e08a56d",
		"562949953421312":     "02adde4b466a9d7e59386b6a701a39717c53f30c4810613c1b55e6b6da43b7bc9a",
		"1125899906842624":    "038eeda11f78ce05c774f30e393cda075192b890d68590813ff46362548528dca9",
		"2251799813685248":    "02ec13e0058b196db80f7079d329333b330dc30c000dbdd7397cbbc5a37a664c4f",
		"4503599627370496":    "02d2d162db63675bd04f7d56df04508840f41e2ad87312a3c93041b494efe80a73",
		"9007199254740992":    "0356969d6aef2bb40121dbd07c68b6102339f4ea8e674a9008bb69506795998f49",
		"18014398509481984":   "02f4e667567ebb9f4e6e180a4113bb071c48855f657766bb5e9c776a880335d1d6",
		"36028797018963968":   "0385b4fe35e41703d7a657d957c67bb536629de57b7e6ee6fe2130728ef0fc90b0",
		"72057594037927936":   "02b2bc1968a6fddbcc78fb9903940524824b5f5bed329c6ad48a19b56068c144fd",
		"144115188075855872":  "02e0dbb24f1d288a693e8a49bc14264d1276be16972131520cf9e055ae92fba19a",
		"288230376151711744":  "03efe75c106f931a525dc2d653ebedddc413a2c7d8cb9da410893ae7d2fa7d19cc",
		"576460752303423488":  "02c7ec2bd9508a7fc03f73c7565dc600b30fd86f3d305f8f139c45c404a52d958a",
		"1152921504606846976": "035a6679c6b25e68ff4e29d1c7ef87f21e0a8fc574f6a08c1aa45ff352c1d59f06",
		"2305843009213693952": "033cdc225962c052d485f7cfbf55a5b2367d200fe1fe4373a347deb4cc99e9a099",
		"4611686018427387904": "024a4b806cf413d14b294719090a9da36ba75209c7657135ad09bc65328fba9e6f",
		"9223372036854775808": "0377a6fe114e291a8d8e991627c38001c8305b23b9e98b1c7b1893f5cd0dda6cad",
	}
	keysMap := make(map[uint64]*secp256k1.PublicKey)

	for key, val := range keysStringMap {
		// Parse the key as big.Int then to uint64 (safe since JSON keys are ≤ 2^63)
		keyInt, ok := new(big.Int).SetString(key, 10)
		if !ok {
			t.Fatalf("invalid key: %s", key)
		}
		if !keyInt.IsUint64() {
			t.Fatalf("key too large for uint64: %s", key)
		}
		uKey := keyInt.Uint64()

		// Decode hex string to bytes
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("invalid hex for key %s: %v", key, err)
		}

		// Parse compressed secp256k1 public key
		pk, err := btcec.ParsePubKey(b)
		if err != nil {
			t.Fatalf("invalid pubkey for key %s: %v", key, err)
		}

		keysMap[uKey] = pk
	}

	pubkeyList := convertPubkeysMapToOrderArray(keysMap)

	finalExpiry := time.Unix(2059210353, 0)
	keysetId := DeriveKeysetIdV2(pubkeyList, cashu.Sat.String(), &finalExpiry)

	if keysetId != "0125bc634e270ad7e937af5b957f8396bb627d73f6e1fd2ffe4294c26b57daf9e0" {
		t.Errorf("keyset id is not correct.")
	}
}

// V2 Generation keysets
func TestKeysetIdGenerationV2Vector3(t *testing.T) {
	keysStringMap := map[string]string{
		"1":                   "03ba786a2c0745f8c30e490288acd7a72dd53d65afd292ddefa326a4a3fa14c566",
		"2":                   "03361cd8bd1329fea797a6add1cf1990ffcf2270ceb9fc81eeee0e8e9c1bd0cdf5",
		"4":                   "036e378bcf78738ddf68859293c69778035740e41138ab183c94f8fee7572214c7",
		"8":                   "03909d73beaf28edfb283dbeb8da321afd40651e8902fcf5454ecc7d69788626c0",
		"16":                  "028a36f0e6638ea7466665fe174d958212723019ec08f9ce6898d897f88e68aa5d",
		"32":                  "03a97a40e146adee2687ac60c2ba2586a90f970de92a9d0e6cae5a4b9965f54612",
		"64":                  "03ce86f0c197aab181ddba0cfc5c5576e11dfd5164d9f3d4a3fc3ffbbf2e069664",
		"128":                 "0284f2c06d938a6f78794814c687560a0aabab19fe5e6f30ede38e113b132a3cb9",
		"256":                 "03b99f475b68e5b4c0ba809cdecaae64eade2d9787aa123206f91cd61f76c01459",
		"512":                 "03d4db82ea19a44d35274de51f78af0a710925fe7d9e03620b84e3e9976e3ac2eb",
		"1024":                "031fbd4ba801870871d46cf62228a1b748905ebc07d3b210daf48de229e683f2dc",
		"2048":                "0276cedb9a3b160db6a158ad4e468d2437f021293204b3cd4bf6247970d8aff54b",
		"4096":                "02fc6b89b403ee9eb8a7ed457cd3973638080d6e04ca8af7307c965c166b555ea2",
		"8192":                "0320265583e916d3a305f0d2687fcf2cd4e3cd03a16ea8261fda309c3ec5721e21",
		"16384":               "036e41de58fdff3cb1d8d713f48c63bc61fa3b3e1631495a444d178363c0d2ed50",
		"32768":               "0365438f613f19696264300b069d1dad93f0c60a37536b72a8ab7c7366a5ee6c04",
		"65536":               "02408426cfb6fc86341bac79624ba8708a4376b2d92debdf4134813f866eb57a8d",
		"131072":              "031063e9f11c94dc778c473e968966eac0e70b7145213fbaff5f7a007e71c65f41",
		"262144":              "02f2a3e808f9cd168ec71b7f328258d0c1dda250659c1aced14c7f5cf05aab4328",
		"524288":              "038ac10de9f1ff9395903bb73077e94dbf91e9ef98fd77d9a2debc5f74c575bc86",
		"1048576":             "0203eaee4db749b0fc7c49870d082024b2c31d889f9bc3b32473d4f1dfa3625788",
		"2097152":             "033cdb9d36e1e82ae652b7b6a08e0204569ec7ff9ebf85d80a02786dc7fe00b04c",
		"4194304":             "02c8b73f4e3a470ae05e5f2fe39984d41e9f6ae7be9f3b09c9ac31292e403ac512",
		"8388608":             "025bbe0cfce8a1f4fbd7f3a0d4a09cb6badd73ef61829dc827aa8a98c270bc25b0",
		"16777216":            "037eec3d1651a30a90182d9287a5c51386fe35d4a96839cf7969c6e2a03db1fc21",
		"33554432":            "03280576b81a04e6abd7197f305506476f5751356b7643988495ca5c3e14e5c262",
		"67108864":            "03268bfb05be1dbb33ab6e7e00e438373ca2c9b9abc018fdb452d0e1a0935e10d3",
		"134217728":           "02573b68784ceba9617bbcc7c9487836d296aa7c628c3199173a841e7a19798020",
		"268435456":           "0234076b6e70f7fbf755d2227ecc8d8169d662518ee3a1401f729e2a12ccb2b276",
		"536870912":           "03015bd88961e2a466a2163bd4248d1d2b42c7c58a157e594785e7eb34d880efc9",
		"1073741824":          "02c9b076d08f9020ebee49ac8ba2610b404d4e553a4f800150ceb539e9421aaeee",
		"2147483648":          "034d592f4c366afddc919a509600af81b489a03caf4f7517c2b3f4f2b558f9a41a",
		"4294967296":          "037c09ecb66da082981e4cbdb1ac65c0eb631fc75d85bed13efb2c6364148879b5",
		"8589934592":          "02b4ebb0dda3b9ad83b39e2e31024b777cc0ac205a96b9a6cfab3edea2912ed1b3",
		"17179869184":         "026cc4dacdced45e63f6e4f62edbc5779ccd802e7fabb82d5123db879b636176e9",
		"34359738368":         "02b2cee01b7d8e90180254459b8f09bbea9aad34c3a2fd98c85517ecfc9805af75",
		"68719476736":         "037a0c0d564540fc574b8bfa0253cca987b75466e44b295ed59f6f8bd41aace754",
		"137438953472":        "021df6585cae9b9ca431318a713fd73dbb76b3ef5667957e8633bca8aaa7214fb6",
		"274877906944":        "02b8f53dde126f8c85fa5bb6061c0be5aca90984ce9b902966941caf963648d53a",
		"549755813888":        "029cc8af2840d59f1d8761779b2496623c82c64be8e15f9ab577c657c6dd453785",
		"1099511627776":       "03e446fdb84fad492ff3a25fc1046fb9a93a5b262ebcd0151caa442ea28959a38a",
		"2199023255552":       "02d6b25bd4ab599dd0818c55f75702fde603c93f259222001246569018842d3258",
		"4398046511104":       "03397b522bb4e156ec3952d3f048e5a986c20a00718e5e52cd5718466bf494156a",
		"8796093022208":       "02d1fb9e78262b5d7d74028073075b80bb5ab281edcfc3191061962c1346340f1e",
		"17592186044416":      "030d3f2ad7a4ca115712ff7f140434f802b19a4c9b2dd1c76f3e8e80c05c6a9310",
		"35184372088832":      "03e325b691f292e1dfb151c3fb7cad440b225795583c32e24e10635a80e4221c06",
		"70368744177664":      "03bee8f64d88de3dee21d61f89efa32933da51152ddbd67466bef815e9f93f8fd1",
		"140737488355328":     "0327244c9019a4892e1f04ba3bf95fe43b327479e2d57c25979446cc508cd379ed",
		"281474976710656":     "02fb58522cd662f2f8b042f8161caae6e45de98283f74d4e99f19b0ea85e08a56d",
		"562949953421312":     "02adde4b466a9d7e59386b6a701a39717c53f30c4810613c1b55e6b6da43b7bc9a",
		"1125899906842624":    "038eeda11f78ce05c774f30e393cda075192b890d68590813ff46362548528dca9",
		"2251799813685248":    "02ec13e0058b196db80f7079d329333b330dc30c000dbdd7397cbbc5a37a664c4f",
		"4503599627370496":    "02d2d162db63675bd04f7d56df04508840f41e2ad87312a3c93041b494efe80a73",
		"9007199254740992":    "0356969d6aef2bb40121dbd07c68b6102339f4ea8e674a9008bb69506795998f49",
		"18014398509481984":   "02f4e667567ebb9f4e6e180a4113bb071c48855f657766bb5e9c776a880335d1d6",
		"36028797018963968":   "0385b4fe35e41703d7a657d957c67bb536629de57b7e6ee6fe2130728ef0fc90b0",
		"72057594037927936":   "02b2bc1968a6fddbcc78fb9903940524824b5f5bed329c6ad48a19b56068c144fd",
		"144115188075855872":  "02e0dbb24f1d288a693e8a49bc14264d1276be16972131520cf9e055ae92fba19a",
		"288230376151711744":  "03efe75c106f931a525dc2d653ebedddc413a2c7d8cb9da410893ae7d2fa7d19cc",
		"576460752303423488":  "02c7ec2bd9508a7fc03f73c7565dc600b30fd86f3d305f8f139c45c404a52d958a",
		"1152921504606846976": "035a6679c6b25e68ff4e29d1c7ef87f21e0a8fc574f6a08c1aa45ff352c1d59f06",
		"2305843009213693952": "033cdc225962c052d485f7cfbf55a5b2367d200fe1fe4373a347deb4cc99e9a099",
		"4611686018427387904": "024a4b806cf413d14b294719090a9da36ba75209c7657135ad09bc65328fba9e6f",
		"9223372036854775808": "0377a6fe114e291a8d8e991627c38001c8305b23b9e98b1c7b1893f5cd0dda6cad",
	}
	keysMap := make(map[uint64]*secp256k1.PublicKey)

	for key, val := range keysStringMap {
		// Parse the key as big.Int then to uint64 (safe since JSON keys are ≤ 2^63)
		keyInt, ok := new(big.Int).SetString(key, 10)
		if !ok {
			t.Fatalf("invalid key: %s", key)
		}
		if !keyInt.IsUint64() {
			t.Fatalf("key too large for uint64: %s", key)
		}
		uKey := keyInt.Uint64()

		// Decode hex string to bytes
		b, err := hex.DecodeString(val)
		if err != nil {
			t.Fatalf("invalid hex for key %s: %v", key, err)
		}

		// Parse compressed secp256k1 public key
		pk, err := btcec.ParsePubKey(b)
		if err != nil {
			t.Fatalf("invalid pubkey for key %s: %v", key, err)
		}

		keysMap[uKey] = pk
	}

	pubkeyList := convertPubkeysMapToOrderArray(keysMap)
	keysetId := DeriveKeysetIdV2(pubkeyList, cashu.Sat.String(), nil)

	if keysetId != "016d72f27c8d22808ad66d1959b3dab83af17e2510db7ffd57d2365d9eec3ced75" {
		t.Errorf("keyset id is not correct.")
	}
}
