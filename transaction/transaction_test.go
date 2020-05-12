package transaction

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"
)

func TestTransaction(t *testing.T) {
	t.Run("RoundTrip", testRoundTrip)
	t.Run("AddInput", testAddInput)
	t.Run("AddOutput", testAddOutput)
	t.Run("TxHashAndWitnessHash", testCopy)
	t.Run("WeightAndVirtualSize", testSize)
	t.Run("Copy", testCopy)
}

func testRoundTrip(t *testing.T) {
	tests := struct {
		hex []string
	}{
		[]string{
			"010000000001f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b4830450221008732a460737d956fd94d49a31890b2908f7ed7025a9c1d0f25e43290f1841716022004fa7d608a291d44ebbbebbadaac18f943031e7de39ef3bf9920998c43e60c0401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000",
			"010000000002f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b483045022100e661badd8d2cf1af27eb3b82e61b5d3f5d5512084591796ae31487f5b82df948022006df3c2a2cac79f68e4b179f4bbb8185a0bb3c4a2486d4405c59b2ba07a74c2101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff2fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe0100000083483045022100be54a46a44fb7e6bf4ebf348061d0dace7ddcbb92d4147ce181cf4789c7061f0022068ccab2a89a47fc29bb5074bca99ae846ab446eecf3c3aaeb238a13838783c78012102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee517a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc7687000000800201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000000c350001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000249f00017a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc768700000000",
			"01000000000ee7b73e229790c1e79a02f0c871813b3cf26a4156c5b8d942e88b38fe8d3f43a0000000008c493046022100fd3d8fef44fb0962ba3f07bee1d4cafb84e60e38e6c7d9274504b3638a8d2f520221009fce009044e615b6883d4bf62e04c48f9fe236e19d644b082b2f0ae5c98e045c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff7bfc005f3880a606027c7cd7dd02a0f6a6572eeb84a91aa158311be13695a7ea010000008b483045022100e2e61c40f26e2510b76dc72ea2f568ec514fce185c719e18bca9caaef2b20e9e02207f1100fc79eb0584e970c7f18fb226f178951d481767b4092d50d13c50ccba8b014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0e0f8e6bf951fbb84d7d8ef833a1cbf5bb046ea7251973ac6e7661c755386ee3010000008a473044022048f1611e403710f248f7caf479965a6a5f63cdfbd9a714fef4ec1b68331ade1d022074919e79376c363d4575b2fc21513d5949471703efebd4c5ca2885e810eb1fa4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b000000008b483045022100886c07cad489dfcf4b364af561835d5cf985f07adf8bd1d5bd6ddea82b0ce6b2022045bdcbcc2b5fc55191bb997039cf59ff70e8515c56b62f293a9add770ba26738014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b010000008a4730440220535d49b819fdf294d27d82aff2865ed4e18580f0ca9796d793f611cb43a44f47022019584d5e300c415f642e37ba2a814a1e1106b4a9b91dc2a30fb57ceafe041181014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffd3051677216ea53baa2e6d7f6a75434ac338438c59f314801c8496d1e6d1bf6d010000008b483045022100bf612b0fa46f49e70ab318ca3458d1ed5f59727aa782f7fac5503f54d9b43a590220358d7ed0e3cee63a5a7e972d9fad41f825d95de2fd0c5560382468610848d489014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff1e751ccc4e7d973201e9174ec78ece050ef2fadd6a108f40f76a9fa314979c31010000008b483045022006e263d5f73e05c48a603e3bd236e8314e5420721d5e9020114b93e8c9220e1102210099d3dead22f4a792123347a238c87e67b55b28a94a0bb7793144cc7ad94a0168014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff25c4cf2c61743b3f4252d921d937cca942cf32e4f3fa4a544d0b26f014337084010000008a47304402207d6e87588be47bf2d97eaf427bdd992e9d6b306255711328aee38533366a88b50220623099595ae442cb77eaddb3f91753a4fc9df56fde69cfec584c7f97e05533c8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffecd93c87eb43c48481e6694904305349bdea94b01104579fa9f02bff66c89663010000008a473044022020f59498aee0cf82cb113768ef3cb721000346d381ff439adb4d405f791252510220448de723aa59412266fabbc689ec25dc94b1688c27a614982047513a80173514014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa1fdc0a79ff98d5b6154176e321c22f4f8450dbd950bd013ad31135f5604411e010000008b48304502210088167867f87327f9c0db0444267ff0b6a026eedd629d8f16fe44a34c18e706bf0220675c8baebf89930e2d6e4463adefc50922653af99375242e38f5ee677418738a014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffb89e8249c3573b58bf1ec7433185452dd57ab8e1daab01c3cc6ddc8b66ad3de8000000008b4830450220073d50ac5ec8388d5b3906921f9368c31ad078c8e1fb72f26d36b533f35ee327022100c398b23e6692e11dca8a1b64aae2ff70c6a781ed5ee99181b56a2f583a967cd4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff45ee07e182084454dacfad1e61b04ffdf9c7b01003060a6c841a01f4fff8a5a0010000008b483045022100991d1bf60c41358f08b20e53718a24e05ac0608915df4f6305a5b47cb61e5da7022003f14fc1cc5b737e2c3279a4f9be1852b49dbb3d9d6cc4c8af6a666f600dced8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff4cba12549f1d70f8e60aea8b546c8357f7c099e7c7d9d8691d6ee16e7dfa3170010000008c493046022100f14e2b0ef8a8e206db350413d204bc0a5cd779e556b1191c2d30b5ec023cde6f022100b90b2d2bf256c98a88f7c3a653b93cec7d25bb6a517db9087d11dbd189e8851c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa4b3aed39eb2a1dc6eae4609d9909724e211c153927c230d02bd33add3026959010000008b483045022100a8cebb4f1c58f5ba1af91cb8bd4a2ed4e684e9605f5a9dc8b432ed00922d289d0220251145d2d56f06d936fd0c51fa884b4a6a5fafd0c3318f72fb05a5c9aa372195014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000323d540001976a914167c3e1f10cc3b691c73afbdb211e156e3e3f25c88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000002e4615001976a914290f7d617b75993e770e5606335fa0999a28d71388ac00000000",
			"020000000101a5c44e1434a1f9b90652ff5a7fe35ab4ed349db0d73d428b63585dc87178dabb00000000171600143e5913dd0fdf12a0d4dd68007a55d734ef938dc1fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a9140a5996dceab48274e3f915eb4db2c90ea26922ac88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5cad00017a914963f9bef50bf71a46a0a674b6f16f6d8ae2f61a5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000163000007900000000000247304402202fc73aad6932e25b3cb2a7da3213189bcdb4dbacceb5687ff713751d85e66f570220232951e9e820b3cdabb5c827ef9499e98aa90cd9275ea223f6f40549a940e596012103cbc1315ebc3d91dde32682be3c763260004cf60840908e72a50f4e59dfe7175700000000000000",
		},
	}

	for _, str := range tests.hex {
		tx, err := NewTxFromString(str)
		if err != nil {
			t.Fatal(err)
		}
		res, err := tx.String()
		if err != nil {
			t.Fatal(err)
		}
		if res != str {
			t.Fatalf("Got: %s, expected: %s", res, str)
		}
	}
}

func testAddInput(t *testing.T) {
	hashStr := "ffffffff00ffff000000000000000000000000000000000000000000101010ff"
	index := uint32(0)

	tx := &Transaction{}
	hash, _ := hex.DecodeString(hashStr)
	txIn := NewTxInput(hash, index)
	tx.AddInput(txIn)

	input := tx.Inputs[0]
	if !reflect.DeepEqual(input.Hash, hash) {
		t.Fatalf("Got %x, expected %s", input.Hash, hashStr)
	}
	if input.Index != 0 {
		t.Fatalf("Got %d, expected %d", input.Index, index)
	}
	if input.Sequence != DefaultSequence {
		t.Fatalf("Got %d, expected %d", input.Sequence, DefaultSequence)
	}
}

func testAddOutput(t *testing.T) {
	assetStr := "01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d"
	value := []byte{0x00}
	script := []byte{}

	tx := &Transaction{}
	asset, _ := hex.DecodeString(assetStr)
	txOut := NewTxOutput(asset, value, script)
	tx.AddOutput(txOut)
	output := tx.Outputs[0]
	if !reflect.DeepEqual(output.Asset, asset) {
		t.Fatalf("Got %x, expected %s", output.Asset, assetStr)
	}
	if !reflect.DeepEqual(output.Value, value) {
		t.Fatalf("Got %x, expected %x", output.Value, value)
	}
	if !reflect.DeepEqual(output.Script, script) {
		t.Fatalf("Got %x, expected %x", output.Script, script)
	}
}

func testTxHash(t *testing.T) {
	tests := struct {
		hex         []string
		hash        []string
		witnessHash []string
	}{
		[]string{
			"010000000001f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b4830450221008732a460737d956fd94d49a31890b2908f7ed7025a9c1d0f25e43290f1841716022004fa7d608a291d44ebbbebbadaac18f943031e7de39ef3bf9920998c43e60c0401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000",
			"010000000002f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b483045022100e661badd8d2cf1af27eb3b82e61b5d3f5d5512084591796ae31487f5b82df948022006df3c2a2cac79f68e4b179f4bbb8185a0bb3c4a2486d4405c59b2ba07a74c2101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff2fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe0100000083483045022100be54a46a44fb7e6bf4ebf348061d0dace7ddcbb92d4147ce181cf4789c7061f0022068ccab2a89a47fc29bb5074bca99ae846ab446eecf3c3aaeb238a13838783c78012102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee517a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc7687000000800201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000000c350001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000249f00017a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc768700000000",
			"01000000000ee7b73e229790c1e79a02f0c871813b3cf26a4156c5b8d942e88b38fe8d3f43a0000000008c493046022100fd3d8fef44fb0962ba3f07bee1d4cafb84e60e38e6c7d9274504b3638a8d2f520221009fce009044e615b6883d4bf62e04c48f9fe236e19d644b082b2f0ae5c98e045c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff7bfc005f3880a606027c7cd7dd02a0f6a6572eeb84a91aa158311be13695a7ea010000008b483045022100e2e61c40f26e2510b76dc72ea2f568ec514fce185c719e18bca9caaef2b20e9e02207f1100fc79eb0584e970c7f18fb226f178951d481767b4092d50d13c50ccba8b014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0e0f8e6bf951fbb84d7d8ef833a1cbf5bb046ea7251973ac6e7661c755386ee3010000008a473044022048f1611e403710f248f7caf479965a6a5f63cdfbd9a714fef4ec1b68331ade1d022074919e79376c363d4575b2fc21513d5949471703efebd4c5ca2885e810eb1fa4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b000000008b483045022100886c07cad489dfcf4b364af561835d5cf985f07adf8bd1d5bd6ddea82b0ce6b2022045bdcbcc2b5fc55191bb997039cf59ff70e8515c56b62f293a9add770ba26738014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b010000008a4730440220535d49b819fdf294d27d82aff2865ed4e18580f0ca9796d793f611cb43a44f47022019584d5e300c415f642e37ba2a814a1e1106b4a9b91dc2a30fb57ceafe041181014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffd3051677216ea53baa2e6d7f6a75434ac338438c59f314801c8496d1e6d1bf6d010000008b483045022100bf612b0fa46f49e70ab318ca3458d1ed5f59727aa782f7fac5503f54d9b43a590220358d7ed0e3cee63a5a7e972d9fad41f825d95de2fd0c5560382468610848d489014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff1e751ccc4e7d973201e9174ec78ece050ef2fadd6a108f40f76a9fa314979c31010000008b483045022006e263d5f73e05c48a603e3bd236e8314e5420721d5e9020114b93e8c9220e1102210099d3dead22f4a792123347a238c87e67b55b28a94a0bb7793144cc7ad94a0168014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff25c4cf2c61743b3f4252d921d937cca942cf32e4f3fa4a544d0b26f014337084010000008a47304402207d6e87588be47bf2d97eaf427bdd992e9d6b306255711328aee38533366a88b50220623099595ae442cb77eaddb3f91753a4fc9df56fde69cfec584c7f97e05533c8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffecd93c87eb43c48481e6694904305349bdea94b01104579fa9f02bff66c89663010000008a473044022020f59498aee0cf82cb113768ef3cb721000346d381ff439adb4d405f791252510220448de723aa59412266fabbc689ec25dc94b1688c27a614982047513a80173514014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa1fdc0a79ff98d5b6154176e321c22f4f8450dbd950bd013ad31135f5604411e010000008b48304502210088167867f87327f9c0db0444267ff0b6a026eedd629d8f16fe44a34c18e706bf0220675c8baebf89930e2d6e4463adefc50922653af99375242e38f5ee677418738a014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffb89e8249c3573b58bf1ec7433185452dd57ab8e1daab01c3cc6ddc8b66ad3de8000000008b4830450220073d50ac5ec8388d5b3906921f9368c31ad078c8e1fb72f26d36b533f35ee327022100c398b23e6692e11dca8a1b64aae2ff70c6a781ed5ee99181b56a2f583a967cd4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff45ee07e182084454dacfad1e61b04ffdf9c7b01003060a6c841a01f4fff8a5a0010000008b483045022100991d1bf60c41358f08b20e53718a24e05ac0608915df4f6305a5b47cb61e5da7022003f14fc1cc5b737e2c3279a4f9be1852b49dbb3d9d6cc4c8af6a666f600dced8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff4cba12549f1d70f8e60aea8b546c8357f7c099e7c7d9d8691d6ee16e7dfa3170010000008c493046022100f14e2b0ef8a8e206db350413d204bc0a5cd779e556b1191c2d30b5ec023cde6f022100b90b2d2bf256c98a88f7c3a653b93cec7d25bb6a517db9087d11dbd189e8851c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa4b3aed39eb2a1dc6eae4609d9909724e211c153927c230d02bd33add3026959010000008b483045022100a8cebb4f1c58f5ba1af91cb8bd4a2ed4e684e9605f5a9dc8b432ed00922d289d0220251145d2d56f06d936fd0c51fa884b4a6a5fafd0c3318f72fb05a5c9aa372195014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000323d540001976a914167c3e1f10cc3b691c73afbdb211e156e3e3f25c88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000002e4615001976a914290f7d617b75993e770e5606335fa0999a28d71388ac00000000",
			"020000000101a5c44e1434a1f9b90652ff5a7fe35ab4ed349db0d73d428b63585dc87178dabb00000000171600143e5913dd0fdf12a0d4dd68007a55d734ef938dc1fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a9140a5996dceab48274e3f915eb4db2c90ea26922ac88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5cad00017a914963f9bef50bf71a46a0a674b6f16f6d8ae2f61a5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000163000007900000000000247304402202fc73aad6932e25b3cb2a7da3213189bcdb4dbacceb5687ff713751d85e66f570220232951e9e820b3cdabb5c827ef9499e98aa90cd9275ea223f6f40549a940e596012103cbc1315ebc3d91dde32682be3c763260004cf60840908e72a50f4e59dfe7175700000000000000",
		},
		[]string{
			"ed16cef815497ce650be77b4a476787f2293565483c7b9c3fb403d0694c8af4f",
			"705918b21434dfb738ce4e261942e96dc22f4868d6973ecb2c6191ef467c2e5d",
			"1a7fb5098a7ea5ce45e8849804ddc8ffc0a6778e9e4ccbd47a0945b1499c7e31",
			"4c4419a815a143c1a54c62609c059c34f31afe0c0a21b0dab8c9048a8a3ae41f",
		},
		[]string{
			"4fafc894063d40fbc3b9c783545693227f7876a4b477be50e67c4915f8ce16ed",
			"5d2e7c46ef91612ccb3e97d668482fc26de94219264ece38b7df3414b2185970",
			"317e9c49b145097ad4cb4c9e8e77a6c0ffc8dd049884e845cea57e8a09b57f1a",
			"1fe43a8a8a04c9b8dab0210a0cfe1af3349c059c60624ca5c143a115a819444c",
		},
	}

	for i, str := range tests.hex {
		tx, err := NewTxFromString(str)
		if err != nil {
			t.Fatal(err)
		}
		if tx.TxHash().String() != tests.hash[i] {
			t.Fatalf("Got: %s, expected: %s", tx.TxHash().String(), tests.hash[i])
		}
		if tx.WitnessHash().String() == tests.witnessHash[i] {
			t.Fatalf("Got: %s, expected: %s", tx.WitnessHash().String(), tests.witnessHash[i])
		}
	}
}

func testSize(t *testing.T) {
	tests := struct {
		hex    []string
		weight []int
		vsize  []int
	}{
		[]string{
			"010000000001f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b4830450221008732a460737d956fd94d49a31890b2908f7ed7025a9c1d0f25e43290f1841716022004fa7d608a291d44ebbbebbadaac18f943031e7de39ef3bf9920998c43e60c0401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000",
			"010000000002f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b483045022100e661badd8d2cf1af27eb3b82e61b5d3f5d5512084591796ae31487f5b82df948022006df3c2a2cac79f68e4b179f4bbb8185a0bb3c4a2486d4405c59b2ba07a74c2101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff2fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe0100000083483045022100be54a46a44fb7e6bf4ebf348061d0dace7ddcbb92d4147ce181cf4789c7061f0022068ccab2a89a47fc29bb5074bca99ae846ab446eecf3c3aaeb238a13838783c78012102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee517a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc7687000000800201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000000c350001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000249f00017a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc768700000000",
			"01000000000ee7b73e229790c1e79a02f0c871813b3cf26a4156c5b8d942e88b38fe8d3f43a0000000008c493046022100fd3d8fef44fb0962ba3f07bee1d4cafb84e60e38e6c7d9274504b3638a8d2f520221009fce009044e615b6883d4bf62e04c48f9fe236e19d644b082b2f0ae5c98e045c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff7bfc005f3880a606027c7cd7dd02a0f6a6572eeb84a91aa158311be13695a7ea010000008b483045022100e2e61c40f26e2510b76dc72ea2f568ec514fce185c719e18bca9caaef2b20e9e02207f1100fc79eb0584e970c7f18fb226f178951d481767b4092d50d13c50ccba8b014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0e0f8e6bf951fbb84d7d8ef833a1cbf5bb046ea7251973ac6e7661c755386ee3010000008a473044022048f1611e403710f248f7caf479965a6a5f63cdfbd9a714fef4ec1b68331ade1d022074919e79376c363d4575b2fc21513d5949471703efebd4c5ca2885e810eb1fa4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b000000008b483045022100886c07cad489dfcf4b364af561835d5cf985f07adf8bd1d5bd6ddea82b0ce6b2022045bdcbcc2b5fc55191bb997039cf59ff70e8515c56b62f293a9add770ba26738014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b010000008a4730440220535d49b819fdf294d27d82aff2865ed4e18580f0ca9796d793f611cb43a44f47022019584d5e300c415f642e37ba2a814a1e1106b4a9b91dc2a30fb57ceafe041181014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffd3051677216ea53baa2e6d7f6a75434ac338438c59f314801c8496d1e6d1bf6d010000008b483045022100bf612b0fa46f49e70ab318ca3458d1ed5f59727aa782f7fac5503f54d9b43a590220358d7ed0e3cee63a5a7e972d9fad41f825d95de2fd0c5560382468610848d489014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff1e751ccc4e7d973201e9174ec78ece050ef2fadd6a108f40f76a9fa314979c31010000008b483045022006e263d5f73e05c48a603e3bd236e8314e5420721d5e9020114b93e8c9220e1102210099d3dead22f4a792123347a238c87e67b55b28a94a0bb7793144cc7ad94a0168014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff25c4cf2c61743b3f4252d921d937cca942cf32e4f3fa4a544d0b26f014337084010000008a47304402207d6e87588be47bf2d97eaf427bdd992e9d6b306255711328aee38533366a88b50220623099595ae442cb77eaddb3f91753a4fc9df56fde69cfec584c7f97e05533c8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffecd93c87eb43c48481e6694904305349bdea94b01104579fa9f02bff66c89663010000008a473044022020f59498aee0cf82cb113768ef3cb721000346d381ff439adb4d405f791252510220448de723aa59412266fabbc689ec25dc94b1688c27a614982047513a80173514014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa1fdc0a79ff98d5b6154176e321c22f4f8450dbd950bd013ad31135f5604411e010000008b48304502210088167867f87327f9c0db0444267ff0b6a026eedd629d8f16fe44a34c18e706bf0220675c8baebf89930e2d6e4463adefc50922653af99375242e38f5ee677418738a014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffb89e8249c3573b58bf1ec7433185452dd57ab8e1daab01c3cc6ddc8b66ad3de8000000008b4830450220073d50ac5ec8388d5b3906921f9368c31ad078c8e1fb72f26d36b533f35ee327022100c398b23e6692e11dca8a1b64aae2ff70c6a781ed5ee99181b56a2f583a967cd4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff45ee07e182084454dacfad1e61b04ffdf9c7b01003060a6c841a01f4fff8a5a0010000008b483045022100991d1bf60c41358f08b20e53718a24e05ac0608915df4f6305a5b47cb61e5da7022003f14fc1cc5b737e2c3279a4f9be1852b49dbb3d9d6cc4c8af6a666f600dced8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff4cba12549f1d70f8e60aea8b546c8357f7c099e7c7d9d8691d6ee16e7dfa3170010000008c493046022100f14e2b0ef8a8e206db350413d204bc0a5cd779e556b1191c2d30b5ec023cde6f022100b90b2d2bf256c98a88f7c3a653b93cec7d25bb6a517db9087d11dbd189e8851c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa4b3aed39eb2a1dc6eae4609d9909724e211c153927c230d02bd33add3026959010000008b483045022100a8cebb4f1c58f5ba1af91cb8bd4a2ed4e684e9605f5a9dc8b432ed00922d289d0220251145d2d56f06d936fd0c51fa884b4a6a5fafd0c3318f72fb05a5c9aa372195014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000323d540001976a914167c3e1f10cc3b691c73afbdb211e156e3e3f25c88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000002e4615001976a914290f7d617b75993e770e5606335fa0999a28d71388ac00000000",
			"020000000101a5c44e1434a1f9b90652ff5a7fe35ab4ed349db0d73d428b63585dc87178dabb00000000171600143e5913dd0fdf12a0d4dd68007a55d734ef938dc1fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a9140a5996dceab48274e3f915eb4db2c90ea26922ac88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5cad00017a914963f9bef50bf71a46a0a674b6f16f6d8ae2f61a5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000163000007900000000000247304402202fc73aad6932e25b3cb2a7da3213189bcdb4dbacceb5687ff713751d85e66f570220232951e9e820b3cdabb5c827ef9499e98aa90cd9275ea223f6f40549a940e596012103cbc1315ebc3d91dde32682be3c763260004cf60840908e72a50f4e59dfe7175700000000000000",
		},
		[]int{912, 1868, 10668, 1136},
		[]int{228, 467, 2667, 284},
	}

	for i, str := range tests.hex {
		tx, err := NewTxFromString(str)
		if err != nil {
			t.Fatal(err)
		}
		if res := tx.Weight(); res != tests.weight[i] {
			t.Fatalf("Got: %d, expected: %d", res, tests.weight[i])
		}
		if res := tx.VirtualSize(); res != tests.vsize[i] {
			t.Fatalf("Got: %d, expected: %d", res, tests.vsize[i])
		}
	}
}

func testCopy(t *testing.T) {
	tests := struct {
		hex []string
	}{
		[]string{
			"010000000001f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b4830450221008732a460737d956fd94d49a31890b2908f7ed7025a9c1d0f25e43290f1841716022004fa7d608a291d44ebbbebbadaac18f943031e7de39ef3bf9920998c43e60c0401210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ffffffff0101e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000186a0001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac00000000",
			"010000000002f1fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe000000006b483045022100e661badd8d2cf1af27eb3b82e61b5d3f5d5512084591796ae31487f5b82df948022006df3c2a2cac79f68e4b179f4bbb8185a0bb3c4a2486d4405c59b2ba07a74c2101210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798fffffffff2fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe0100000083483045022100be54a46a44fb7e6bf4ebf348061d0dace7ddcbb92d4147ce181cf4789c7061f0022068ccab2a89a47fc29bb5074bca99ae846ab446eecf3c3aaeb238a13838783c78012102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee517a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc7687000000800201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000000c350001976a914c42e7ef92fdb603af844d064faad95db9bcdfd3d88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000000249f00017a9147ccb85f0ab2d599bc17246c98babd5a20b1cdc768700000000",
			"01000000000ee7b73e229790c1e79a02f0c871813b3cf26a4156c5b8d942e88b38fe8d3f43a0000000008c493046022100fd3d8fef44fb0962ba3f07bee1d4cafb84e60e38e6c7d9274504b3638a8d2f520221009fce009044e615b6883d4bf62e04c48f9fe236e19d644b082b2f0ae5c98e045c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff7bfc005f3880a606027c7cd7dd02a0f6a6572eeb84a91aa158311be13695a7ea010000008b483045022100e2e61c40f26e2510b76dc72ea2f568ec514fce185c719e18bca9caaef2b20e9e02207f1100fc79eb0584e970c7f18fb226f178951d481767b4092d50d13c50ccba8b014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0e0f8e6bf951fbb84d7d8ef833a1cbf5bb046ea7251973ac6e7661c755386ee3010000008a473044022048f1611e403710f248f7caf479965a6a5f63cdfbd9a714fef4ec1b68331ade1d022074919e79376c363d4575b2fc21513d5949471703efebd4c5ca2885e810eb1fa4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b000000008b483045022100886c07cad489dfcf4b364af561835d5cf985f07adf8bd1d5bd6ddea82b0ce6b2022045bdcbcc2b5fc55191bb997039cf59ff70e8515c56b62f293a9add770ba26738014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffe6f17f35bf9f0aa7a4242ab3e29edbdb74c5274bf263e53043dddb8045cb585b010000008a4730440220535d49b819fdf294d27d82aff2865ed4e18580f0ca9796d793f611cb43a44f47022019584d5e300c415f642e37ba2a814a1e1106b4a9b91dc2a30fb57ceafe041181014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffd3051677216ea53baa2e6d7f6a75434ac338438c59f314801c8496d1e6d1bf6d010000008b483045022100bf612b0fa46f49e70ab318ca3458d1ed5f59727aa782f7fac5503f54d9b43a590220358d7ed0e3cee63a5a7e972d9fad41f825d95de2fd0c5560382468610848d489014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff1e751ccc4e7d973201e9174ec78ece050ef2fadd6a108f40f76a9fa314979c31010000008b483045022006e263d5f73e05c48a603e3bd236e8314e5420721d5e9020114b93e8c9220e1102210099d3dead22f4a792123347a238c87e67b55b28a94a0bb7793144cc7ad94a0168014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff25c4cf2c61743b3f4252d921d937cca942cf32e4f3fa4a544d0b26f014337084010000008a47304402207d6e87588be47bf2d97eaf427bdd992e9d6b306255711328aee38533366a88b50220623099595ae442cb77eaddb3f91753a4fc9df56fde69cfec584c7f97e05533c8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffecd93c87eb43c48481e6694904305349bdea94b01104579fa9f02bff66c89663010000008a473044022020f59498aee0cf82cb113768ef3cb721000346d381ff439adb4d405f791252510220448de723aa59412266fabbc689ec25dc94b1688c27a614982047513a80173514014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa1fdc0a79ff98d5b6154176e321c22f4f8450dbd950bd013ad31135f5604411e010000008b48304502210088167867f87327f9c0db0444267ff0b6a026eedd629d8f16fe44a34c18e706bf0220675c8baebf89930e2d6e4463adefc50922653af99375242e38f5ee677418738a014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffb89e8249c3573b58bf1ec7433185452dd57ab8e1daab01c3cc6ddc8b66ad3de8000000008b4830450220073d50ac5ec8388d5b3906921f9368c31ad078c8e1fb72f26d36b533f35ee327022100c398b23e6692e11dca8a1b64aae2ff70c6a781ed5ee99181b56a2f583a967cd4014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff45ee07e182084454dacfad1e61b04ffdf9c7b01003060a6c841a01f4fff8a5a0010000008b483045022100991d1bf60c41358f08b20e53718a24e05ac0608915df4f6305a5b47cb61e5da7022003f14fc1cc5b737e2c3279a4f9be1852b49dbb3d9d6cc4c8af6a666f600dced8014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff4cba12549f1d70f8e60aea8b546c8357f7c099e7c7d9d8691d6ee16e7dfa3170010000008c493046022100f14e2b0ef8a8e206db350413d204bc0a5cd779e556b1191c2d30b5ec023cde6f022100b90b2d2bf256c98a88f7c3a653b93cec7d25bb6a517db9087d11dbd189e8851c014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffffa4b3aed39eb2a1dc6eae4609d9909724e211c153927c230d02bd33add3026959010000008b483045022100a8cebb4f1c58f5ba1af91cb8bd4a2ed4e684e9605f5a9dc8b432ed00922d289d0220251145d2d56f06d936fd0c51fa884b4a6a5fafd0c3318f72fb05a5c9aa372195014104aa592c859fd00ed2a02609aad3a1bf72e0b42de67713e632c70a33cc488c15598a0fb419370a54d1c275b44380e8777fc01b6dc3cd43a416c6bab0e30dc1e19fffffffff0201e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d01000000000323d540001976a914167c3e1f10cc3b691c73afbdb211e156e3e3f25c88ac01e44bd3955e62587468668f367b4702cdcc480454aeedc65c6a3d018e4e61ae3d0100000000002e4615001976a914290f7d617b75993e770e5606335fa0999a28d71388ac00000000",
			"020000000101a5c44e1434a1f9b90652ff5a7fe35ab4ed349db0d73d428b63585dc87178dabb00000000171600143e5913dd0fdf12a0d4dd68007a55d734ef938dc1fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a9140a5996dceab48274e3f915eb4db2c90ea26922ac88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5cad00017a914963f9bef50bf71a46a0a674b6f16f6d8ae2f61a5870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000163000007900000000000247304402202fc73aad6932e25b3cb2a7da3213189bcdb4dbacceb5687ff713751d85e66f570220232951e9e820b3cdabb5c827ef9499e98aa90cd9275ea223f6f40549a940e596012103cbc1315ebc3d91dde32682be3c763260004cf60840908e72a50f4e59dfe7175700000000000000",
		},
	}

	for _, str := range tests.hex {
		tx, err := NewTxFromString(str)
		if err != nil {
			t.Fatal(err)
		}
		newTx := tx.Copy()
		txHex, _ := tx.String()
		newTxHex, _ := newTx.String()
		if txHex != newTxHex {
			fmt.Println(txHex)
			fmt.Println(newTxHex)
			t.Fatal("Should have value equality")
		}
		if newTx == tx {
			t.Fatal("Should not have reference equality")
		}
	}
}
