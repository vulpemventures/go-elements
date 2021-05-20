package pegin

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/vulpemventures/go-elements/address"

	"github.com/vulpemventures/go-elements/block"
	"github.com/vulpemventures/go-elements/elementsutil"

	"github.com/btcsuite/btcd/wire"

	"github.com/stretchr/testify/assert"
)

func TestStripWitnessFromBtcTx(t *testing.T) {
	txHex := "020000000001019b7aefabe954160747e2f3ebe27940788abb427ee7dde2c857bf95f7ce8ff2990000000017160014ca4b5c9294aa8b827a639d2610d5747d906488d8feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c40268710161a1e0100000017a914a8fcb1a6a1922012bae14c54caf510326dfa47f98702473044022049500e2cc5b09ec944d9a362bf1789dce07ce81e31a1cb0831a2b3906d53fff902201037a734559bfbfeeff44bbffa66dd14de6c0631eb702a3d29a1349db52010250121038a91c84aaeb1a41fdda631cf02b19fab2329c4ba3a9fe435339b380d80c5374a66000000"
	expected := "02000000019b7aefabe954160747e2f3ebe27940788abb427ee7dde2c857bf95f7ce8ff2990000000017160014ca4b5c9294aa8b827a639d2610d5747d906488d8feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c40268710161a1e0100000017a914a8fcb1a6a1922012bae14c54caf510326dfa47f98766000000"

	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}

	stripedTx, err := StripWitnessFromBtcTx(txBytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, hex.EncodeToString(stripedTx))
}

func TestSerializeValue(t *testing.T) {
	var value int64 = 1000000000
	expected := "00ca9a3b00000000"

	serializedValue, err := SerializeValue(value)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, expected, hex.EncodeToString(serializedValue))
}

func TestSerializeTxOutProof(t *testing.T) {
	txHex := "02000000000101f98f9665468889b67336bdeda87aa7556b465dca2615b42b225f56cd5c2b054c01000000171600140626f9faded4f428f44e87a13ccad4ca464e07b6feffffff0200e1f5050000000017a91472c44f957fc011d97e3406667dca5b1c930c402687182824180100000017a91491c518a33a7061958d1f33b1965ff1dc70abb45f87024730440220121bd7cf7700a670f53023c83e50548d52ceb3df4b4636e3ea6d3ba34137424a02200d6614a949c9cd7bb02fae505b4626b73e3c06901398ae4fcc422d2bd9e89df601210367ffea4c8a61f790a8456a170a744e2f588622a3b0ecc28633e70370bfc9baec00000000"
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}

	var tx wire.MsgTx
	err = tx.BtcDecode(
		bytes.NewReader(txBytes),
		wire.ProtocolVersion,
		wire.LatestEncoding,
	)
	if err != nil {
		t.Fatal(err)
	}
	txHash := tx.TxHash().String()
	t.Log(txHash)

	txOutProof := "00000020fa203873242b50221d533889f7b7906a3946b505b8376e2d751e700010367d5849dfb02557386193ebf0f92a606958cbf249662dddecc55bd9f68d20aec0a226308f9e60ffff7f20000000000200000002d45deb54cebe4d401c5b3504a2c0f1114f29ddd959125c222034cf24484507229daedfd4722343ffb707185e16e9b0479dba6ed147b82c720efc96c3179b5db40105"

	merkleBlock, err := block.NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	exists := false
	for _, v := range merkleBlock.PartialMerkleTree.TxHashes {
		if hex.EncodeToString(elementsutil.ReverseBytes(v)) == txHash {
			exists = true
		}
	}

	assert.Equal(t, true, exists)
}

//TODO remove
func TestB(t *testing.T) {
	txHex := "02000000000101ceeb1b57d62f30725295adb7ca6438f9b6368aa7010d8d11ba281574f88aa25501000000171600149cb04476de48015ab191ee9fe6fe7c496f249dd7feffffff0210161a1e0100000017a9145d060f1cd0770f29049667dcf0d558da22a24b2f8700e1f5050000000017a9144c6cc5ef2d398b5bf312035b92d2f3e20c44c11d8702473044022058af3c0fe35c312c59f63b0f2edbc343f23d637eaf795178d89fb8948437da520220013ca5879bf76045bd00033558267708ee5db10e674329a6844de52e5dc3ea940121025bf45c82323296ad859b34ccab8c5cc7545c3257359ebb594bff69e1b7b50ae197000000"
	txBytes, err := hex.DecodeString(txHex)
	if err != nil {
		t.Fatal(err)
	}

	stripedTx, err := StripWitnessFromBtcTx(txBytes)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(hex.EncodeToString(stripedTx))

	federationScript := "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae"
	fedpegScriptBytes, err := hex.DecodeString(federationScript)
	if err != nil {
		t.Fatal(err)
	}

	pops, err := address.ParseScript(fedpegScriptBytes)
	if err != nil {
		t.Fatal(err)
	}

	if address.IsScriptHash(pops) {
		fmt.Println("JSESSS")
	}
}
