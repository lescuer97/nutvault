package signer

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"
	"nutmix_remote_signer/database"
	"nutmix_remote_signer/utils"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/lescuer97/nutmix/api/cashu"
)

const mintPrivateKey string = "0000000000000000000000000000000000000000000000000000000000000001"

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
	intRef := ParseUnitToIntegerReference(cashu.Sat.String())

	if intRef != 1967237907 {
		t.Errorf("sat bytes are wrong %v", intRef)
	}
}

// Test Vectors Remote signer
func TestMSatConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.Msat.String())

	if intRef != 142929756 {
		t.Errorf("msat bytes are wrong %v", intRef)
	}
}

// Test Vectors Remote signer
func TestEurConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.EUR.String())

	if intRef != 1473545324 {
		t.Errorf("Eur bytes are wrong %v", intRef)
	}
}
func TestUsdConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.USD.String())

	if intRef != 577560378 {
		t.Errorf("USD bytes are wrong %v", intRef)
	}
}

func TestAuthConvertToInteger(t *testing.T) {
	intRef := ParseUnitToIntegerReference(cashu.AUTH.String())

	if intRef != 1222349093 {
		t.Errorf("auth bytes are wrong %v", intRef)
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
		"1":                   "0233501d047ff4058007722d5d24e10a8ff5c723a677be411fff46a3cee9a92cc0",
		"2":                   "03a09803ce40118b8917fafa08409dbe6e8bb36d76c55f4c58400cd720abaf54cb",
		"4":                   "02dac058df2e8611098286ef87ee9698f555548784ab4b1a860c79338073ad8c49",
		"8":                   "025b66b937d65544981817aa9a053a762a7d72a7543c66a54370ea68aa53170a10",
		"16":                  "027cf2ad5fa02b99ea37b305048562828453d89dfa7defcda1c10f6746f25f7541",
		"32":                  "0336033cbbc044737bced1fd40b7f0cb0ce08a83aedaa882ed1ced875a1f517879",
		"64":                  "035be95ecaadbfe67b14f07205d13bbcab5da58bb595c57dfb9b61c5e3e7e4de0e",
		"128":                 "0232c757957a8f5a14e93a9bbe8852c273b985ad238ce9b4d5a16885d8a761462b",
		"256":                 "02cbd889df7d38e95dca2ee0e09bc22e3ae57e95975043854a5560a464f970ac1f",
		"512":                 "02c99a0b72ba8f01c5da765c534e75ae3e5f51e4931bfced18a91df4b9233b168f",
		"1024":                "0320527abb6ae3dd6db9da5041ca941be679e953b446614843af7a4393e9ac96bc",
		"2048":                "033f9276b0c5f73fbeb0130eab5705a8e878f4191fe251a18cbd918cda3c9e2d5e",
		"4096":                "03cf69ed2939be4ac35308560d4423e1a0d96cacf9fe33267c7e6a047bf438e53e",
		"8192":                "027c8bfff71352766c3870e9f5f577830bbb44eadfb757fdff9a8cd209c4b22d76",
		"16384":               "02ea21bd310828b9e46746eba2ae985626b3a2efc2468db66ae480715dc6deec8a",
		"32768":               "027ae7179192282d5b44ac55bff82c13e1ea916ae1edefa33ea64100be7408e015",
		"65536":               "028f333c1beada3445cb62108e35d72199925a055c1e7c102c742e1761770f6c62",
		"131072":              "03de95cae3614499a3df2d412e91aa09ddef8b8d49e8d652e3798419da86958139",
		"262144":              "03c7817c19b4b107eb2ccf2f32b60f9c22a59a1d4a93e492ad01f1505097a654b7",
		"524288":              "028aad03886b6ec6b9f628090e9c151a73f025aa949a9686dac1f0b32995a4e8df",
		"1048576":             "034bf50a5916d9f112b8fbfe82a5ac914b5bec792b107cf25922c9866f002473e8",
		"2097152":             "03d2894e1b1b7ab7497ff69e16d280b630f60ba34fe00edd7c748ae5ee73bc0d1a",
		"4194304":             "0285ba0ee2960927de958610b13d63fc29019407eb32c477d9a2d016fda3062a37",
		"8388608":             "03d7a4b4b1b8d6b9f2b5966e380a62f8efd53f79d1965e076a716d2fb75e9774a1",
		"16777216":            "037a033e2f1df992523df83bcb9aa02cefdadd59882d7949f4500f5493d89fa2fd",
		"33554432":            "03014de7af4809599cabc6d6b30e5121b4a88153eb38a7b66dd8e50e3166215ab0",
		"67108864":            "0240162a1d2eb1841450de53a6244a625922b14006153d5219dad0fcf0c369c497",
		"134217728":           "03f8c6f7b0ee71f66940a33c746c3bf8b1cba793a498dd2fdeb6857552415a4d5d",
		"268435456":           "02dc9de15fa1332f5a2c8f85045ea127cbc3407fb8a844b453f38e1c9cdce9ef87",
		"536870912":           "0291bdcb1719b5bf447b2885efc84061d1de30b9d1f583d25034059457a2fd739e",
		"1073741824":          "02f8a96485e3fa791f57d7f4ef279dd3617b873efbdf673815c49dbf9ce7422b0d",
		"2147483648":          "02ff8cf3e3de985bb2f286c98e335a175b2b53a0e0d7fa1f53d642c95a372329a2",
		"4294967296":          "02d96196cc54e7506bfe9fdb4a0d691eed2948ecb9b8e81d28d27225287ad5debc",
		"8589934592":          "03e64e5664f7ab843f41aaf4c0534d698b3318d140c23cbd2fcc33eece53400dac",
		"17179869184":         "034c9a4bf7b4cb8fac6ace994624e5250ddac5ac84541b6c8bd12b71d22719bb2d",
		"34359738368":         "0313027c2b106c7dcdee0d806c3343026260276c6793d4d1dfdf79aae30875be31",
		"68719476736":         "03081adca96d42cb2ac4ac94e0ea2aac4d9412265ae55ed377e3c0357aa1157253",
		"137438953472":        "02fdc4118761739425220ba87dee5ea9fdc1d581abfcb506fb5afabf76e172b798",
		"274877906944":        "031dd7cd25f761c8f80828b487bab1cef730f68e8d6f2026b443cc7223862f6c73",
		"549755813888":        "02da505eab15744a6fd3fa6b3257bced520d4d294ea94444528fd30d7f90948629",
		"1099511627776":       "02bfc54369099958275376ab030f2a085532c8a00ae4d1bbfa5031c64b42d58a47",
		"2199023255552":       "032241a5d4d1e988b8ae85f68a381df0e40065ae8c81b1c4f7ea31c87eab2c0d81",
		"4398046511104":       "03a681e41990d350cdedd30840f26ad970b4015dd6e6b5c03f7cc99b384bee8762",
		"8796093022208":       "033d5293a33cda29d65058d6d3a4b821472574e92414fa052c79f8bdc1cd72faba",
		"17592186044416":      "033ddfec40622aaf62d672f43fd05ddb396afd7ad9f00daede45102c890d3a012b",
		"35184372088832":      "02564bbdcbed18a8e2d79b2fdad6e5e8a9fe92e853ab23170934d84015cc4b96b0",
		"70368744177664":      "02170950642b94d0ed232370d5dd3630b5eb7e73791447fb961b12d8139de975de",
		"140737488355328":     "02b2add5a6eb5dc06f706e9dba190ba412c2c7ba240284b336b66ef38a39e51f1c",
		"281474976710656":     "03e3e584a4bc1d0a6399f5b6b9355bd67a10ad9f46c8a4283de96854e47eb4357c",
		"562949953421312":     "033821262e6a78f29dad81d3133845883a7632a47f51ab1d99a0eae4a5354eef45",
		"1125899906842624":    "038db672a61c70dc66b504152ea39b607527f2f59e8ebfdf8d955c38e914661534",
		"2251799813685248":    "03dafb9683eac036a422266ddc85b675bf13aeafe0658cad2ec1555c28f4049b28",
		"4503599627370496":    "0351733345d4bb491e27bdb221e382d00f2248f2ee7f04dc6f3faab2692fbd296c",
		"9007199254740992":    "03f930c1e6c154ca169370adbec7691fd9c11245867a37ae086f7547f5c9e8386f",
		"18014398509481984":   "02d700dc30d3cd6be292bddbd5f74c09df784862c785cd763ad6c829be59c21bed",
		"36028797018963968":   "03444b9c312900fffbd478e390aa6fdf9d3ffe230239141ecadf0bcee25e379512",
		"72057594037927936":   "03af7acedfcfcaf83cfdb7d171ef64723286bd6e0ab90f3629e627e77955917776",
		"144115188075855872":  "02e35aef647a881e8c318879fb81b6261df73e385dfbc5ff3fc0ab40f13f5ed560",
		"288230376151711744":  "024558ed8e986901e05839c34d17c261c8d93b8cabb5dee83ab805bb5028e5e463",
		"576460752303423488":  "024f60a89ba055e009d84a90a13a7860a909fb486a8ffb4315c2f59aff6fbfd929",
		"1152921504606846976": "0311b2a5b91dfaebab4fb125338fd38dab72ec5671e6db5f468cb1477970ea3876",
		"2305843009213693952": "02aeaa116d930767b5143cac922511c0e093beee5a2850f67490f5a5bb44a8af76",
		"4611686018427387904": "02bf7003847bc8e7ad35ea5c8975e3fdde8d1c43ef540d250cf2dc75792c733647",
		"9223372036854775808": "0376b06a13092fbb679f6e7a90ce877c37d5a20714a65567177a91a0479b3e86a9",
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
	if hex.EncodeToString(mintKeyset.Id) != "00b5a0580f75cc2f" {
		t.Errorf("id was incorrect. %x", mintKeyset.Id)
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
		Amounts:     []uint64{1},
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
		"1": "025b6c1ca8bb741a6f2321c953266df7bf3f3f2c3be8c54c0a6e41bb00976046a4",
	}

	if hex.EncodeToString(mintKeyset.Id) != "00e1cf6079abb988" {
		t.Errorf("id was incorrect. %x", mintKeyset.Id)
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

func TestCollisionOfUnitError(t *testing.T) {
	keysets := []MintPublicKeyset{{Unit: "SAT"}}
	err := unitStringCollissionCheck(keysets, "sW8W2A_hTH_gapj1_vj5suO3JI_")

	if !errors.Is(err, utils.ErrUnitStringCollision) {
		t.Errorf("error is incorrect. There should have been a keyset collision error: %v", err)

	}
}
