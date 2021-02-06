package pset

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/stretchr/testify/assert"
	"github.com/vulpemventures/go-elements/confidential"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"
	"github.com/vulpemventures/go-elements/transaction"
)

var lbtc = append(
	[]byte{0x01},
	elementsutil.ReverseBytes(h2b(network.Regtest.AssetID))...,
)

func TestRoundTrip(t *testing.T) {
	tests := struct {
		base64 []string
		hex    []string
	}{
		[]string{
			"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",
		},
		[]string{
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f40000000000000000000000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000000000000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000190000000000000010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001030401000000000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a68000000000000010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000019000000000000022020251464420fcc98a2e4cd347afe28a32d769287dacd861476ab858baa43bd308f347304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96ad24ea072d2e63e01010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a680000000000002202026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa47304402201252d7b429dd5fd556fa0962cea9027b924e0919494d3930aa4c0ba41333798402205802cb6163c89644a5ba9830a7a13194a77e71e35593f3ad643b5b20eeee5e7a0101030401000000000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a680000000000002202026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa47304402207897850961700b54908d4188a483050d7ffe25bcc083f5cd0ce15ce3dfc8a33b022001b7b1dd893290c269f2fab3368e3e6316ef8e85e5efbc9d669b87387ee7c52801010304010000000001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
			"70736574ff0100ea02000000000180e510ab7856a0a5cdedfcbb4cec8695349b31854102aa92994f263e34f0649d0000000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faf080001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000002faecfc001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000001f4000000000000000100fd0f010200000000010caf381d44f094661f2da71a11946251a27d656d6c141577e27c483a6d428f01010000006a47304402205ac99f5988d699d6d9f72004098c2e52c8f342838e9009dde33d204108cc930d022077238cd40a4e4234f1e70ceab8fd6b51c53259543872e5d9f4bad544918b82ce012102b5214a4f0d6962fe547f0b9cbb241f9df1b61c3c401dbfb04cdd59efd552bea1ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5df70001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000019000000000000001076a47304402201e868b2bea22df05229746a27e7df2ca0f584880546f7f6d55dad71cbd50d35302203a04a4cc49fca739c8974c97d3de924c99835e15ad1d85b96ad24ea072d2e63e01210251464420fcc98a2e4cd347afe28a32d769287dacd861476ab858baa43bd308f30001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a914659bedb5d3d3c7ab12d7f85323c3a1b6c060efbe88ac0000",
			"70736574ff0100fd1301020000000002e764173b5dacc84c58eeef1650703f954f0f76b5c1622a416e6164b0a21540400100000000ffffffff38ef6a9722772e532395d8293f43638c6b478665aeb0b461fc9929ccace725280100000000ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000007270e00001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000004c4b1a8001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000000258000000000000000100fd5201020000000001e5023b4c497023af19c8a00951f5b689f16dfdd825e2e4239e9f32e40a21fd1f010000006a473044022072e556b51c6e2b15e54762d1577f43f1d40b612d8c0b1fce2e7d07f482a8c93f022031b1f650f1a27f6a39c04dbbe83675e2082b3dbe78ba07fd7a96a6e65a791df0012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000011e188980017a9141d46d41d82f4ed3ef5da0da012ca633fd085ad41870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001076a47304402201252d7b429dd5fd556fa0962cea9027b924e0919494d3930aa4c0ba41333798402205802cb6163c89644a5ba9830a7a13194a77e71e35593f3ad643b5b20eeee5e7a0121026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa000100fd520102000000000196fe39b21f0d4b0caf61c92c254a818a716d131ece745e6599adea35f849b513000000006a47304402206cb0985a0f149b228a652008c25598f087bbe2f7b0553b14ae0ed6e7ce81068b02205a12dbc5b81b55f966e88a12791fd92fd44f9176dfccf0e956a2bc7d37368999012102f9daac6e1cf87759a5b004d429a1f8d68fcb076b7efbbd30b475c4f120de7260ffffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5c6980017a914484550d329861ce6830d208fa66613a9511a8a14870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f5e100001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000001a6800000000000001076a47304402207897850961700b54908d4188a483050d7ffe25bcc083f5cd0ce15ce3dfc8a33b022001b7b1dd893290c269f2fab3368e3e6316ef8e85e5efbc9d669b87387ee7c5280121026dc3f97e2c7c7b3c2dc8d74424a9ebc423603eb416db00a82eb7bd971b2d9ffa0001001976a91439397080b51ef22c59bd7469afacffbeec0da12e88ac0001001976a91450a410115f0a7d8a99472e47d1928ff8086948c888ac0000",
		},
	}

	for _, str := range tests.base64 {
		p, err := NewPsetFromBase64(str)
		if err != nil {
			t.Fatal(err)
		}
		res, err := p.ToBase64()
		if err != nil {
			t.Fatal(err)
		}
		assert.Equal(t, str, res)
	}
}

func TestBroadcastBlindedSwapTx(t *testing.T) {
	/**
	* This test attempts to broadcast a confidential swap transaction
	* composed by 2 P2WPKH confidential input and 3 confidential outputs. The
	* outputs will be a confidential p2wpkh for both the asset, the
	* L-BTC, and another confidential p2wpkh for the change. A 4th
	* unblinded output is for the fees, with empty script.
	**/

	// Generating Alices Keys and Address
	privkeyAlice, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindPrivkeyAlice, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkeyAlice := privkeyAlice.PubKey()
	blindPubkeyAlice := blindPrivkeyAlice.PubKey()
	p2wpkhAlice := payment.FromPublicKey(pubkeyAlice, &network.Regtest, blindPubkeyAlice)
	addressAlice, _ := p2wpkhAlice.ConfidentialWitnessPubKeyHash()

	// Generating Bobs Keys and Address
	privkeyBob, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindPrivkeyBob, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkeyBob := privkeyBob.PubKey()
	blindPubkeyBob := blindPrivkeyBob.PubKey()
	p2wpkhBob := payment.FromPublicKey(pubkeyBob, &network.Regtest, blindPubkeyBob)
	addressBob, _ := p2wpkhBob.ConfidentialWitnessPubKeyHash()

	// Fund Alice address with LBTC.
	if _, err := faucet(addressAlice); err != nil {
		t.Fatal(err)
	}

	// Fund Bob address with an asset.
	_, mintedAsset, err := mint(addressBob, 1000, "VULPEM", "VLP")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)

	// Retrieve Alice utxos.
	utxosAlice, err := unspents(addressAlice)
	if err != nil {
		t.Fatal(err)
	}

	// Retrieve Bob utxos.
	utxosBob, err := unspents(addressBob)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 2 input and 3 outputs.
	// Input From Alice
	txInputHashAlice := elementsutil.ReverseBytes(h2b(utxosAlice[0]["txid"].(string)))
	txInputIndexAlice := uint32(utxosAlice[0]["vout"].(float64))
	txInputAlice := transaction.NewTxInput(txInputHashAlice, txInputIndexAlice)
	// Input From Bob
	txInputHashBob := elementsutil.ReverseBytes(h2b(utxosBob[0]["txid"].(string)))
	txInputIndexBob := uint32(utxosBob[0]["vout"].(float64))
	txInputBob := transaction.NewTxInput(txInputHashBob, txInputIndexBob)

	//// Outputs from Alice
	// LBTC to Bob
	aliceToBobValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	aliceToBobScript := p2wpkhBob.WitnessScript
	aliceToBobOutput := transaction.NewTxOutput(lbtc, aliceToBobValue, aliceToBobScript)
	// Change from/to Alice
	changeScriptAlice := p2wpkhAlice.WitnessScript
	changeValueAlice, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutputAlice := transaction.NewTxOutput(lbtc, changeValueAlice[:], changeScriptAlice)

	// Asset hex
	asset := append([]byte{0x01}, elementsutil.ReverseBytes(h2b(mintedAsset))...)

	//// Outputs from Bob
	// Asset to Alice
	bobToAliceValue, _ := elementsutil.SatoshiToElementsValue(100000000000)
	bobToAliceScript := p2wpkhAlice.WitnessScript
	bobToAliceOutput := transaction.NewTxOutput(asset, bobToAliceValue, bobToAliceScript)

	// Create a new pset with all the outputs that need to be blinded first
	inputs := []*transaction.TxInput{txInputAlice, txInputBob}
	outputs := []*transaction.TxOutput{aliceToBobOutput, changeOutputAlice, bobToAliceOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxos to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	prevTxHexAlice, err := fetchTx(utxosAlice[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	prevTxAlice, _ := transaction.NewTxFromHex(prevTxHexAlice)
	assetCommitmentAlice := h2b(utxosAlice[0]["assetcommitment"].(string))
	valueCommitmentAlice := h2b(utxosAlice[0]["valuecommitment"].(string))
	witnessUtxoAlice := &transaction.TxOutput{
		Asset:           assetCommitmentAlice,
		Value:           valueCommitmentAlice,
		Script:          p2wpkhAlice.WitnessScript,
		Nonce:           prevTxAlice.Outputs[txInputIndexAlice].Nonce,
		RangeProof:      prevTxAlice.Outputs[txInputIndexAlice].RangeProof,
		SurjectionProof: prevTxAlice.Outputs[txInputIndexAlice].SurjectionProof,
	}

	if err := updater.AddInWitnessUtxo(witnessUtxoAlice, 0); err != nil {
		t.Fatal(err)
	}

	prevTxHexBob, err := fetchTx(utxosBob[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	prevTxBob, _ := transaction.NewTxFromHex(prevTxHexBob)
	assetCommitmentBob := h2b(utxosBob[0]["assetcommitment"].(string))
	valueCommitmentBob := h2b(utxosBob[0]["valuecommitment"].(string))
	witnessUtxoBob := &transaction.TxOutput{
		Asset:           assetCommitmentBob,
		Value:           valueCommitmentBob,
		Script:          p2wpkhBob.WitnessScript,
		Nonce:           prevTxBob.Outputs[txInputIndexBob].Nonce,
		RangeProof:      prevTxBob.Outputs[txInputIndexBob].RangeProof,
		SurjectionProof: prevTxBob.Outputs[txInputIndexBob].SurjectionProof,
	}

	if err := updater.AddInWitnessUtxo(witnessUtxoBob, 1); err != nil {
		t.Fatal(err)
	}

	inBlindingPrvKeys := [][]byte{
		blindPrivkeyAlice.Serialize(),
		blindPrivkeyBob.Serialize(),
	}
	outBlindingPrvKeys := [][]byte{
		blindPrivkeyBob.Serialize(),
		blindPrivkeyAlice.Serialize(),
		blindPrivkeyAlice.Serialize(),
	}

	if err := blindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	addFeesToTransaction(p, 500)

	prvKeys := []*btcec.PrivateKey{
		privkeyAlice,
		privkeyBob,
	}
	scripts := [][]byte{
		p2wpkhAlice.Script,
		p2wpkhBob.Script,
	}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedTxP2PKH(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be locked by a P2PKH script,
	* while the outputs will be a legacy P2PKH for the receiver and the same P2PKH for the change.	*
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	**/

	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2pkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2pkh.PubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript := p2pkh.Script
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeScript := p2pkh.Script
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeScript := []byte{}
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	txHex, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := transaction.NewTxFromHex(txHex)

	updater.AddInNonWitnessUtxo(tx, 0)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2pkh.Script}
	if err := signTransaction(p, prvKeys, scripts, false, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedTxP2SH_P2WPKH(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be a legacy input locked by a
	* p2sh(p2wpkh) script, while the outputs will be a legacy p2pkh for the
	* receiver and the same legacy p2sh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	**/

	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	p2sh, _ := payment.FromPayment(p2wpkh)
	address, _ := p2sh.ScriptHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash, _ := hex.DecodeString(utxos[0]["txid"].(string))
	txInputHash = elementsutil.ReverseBytes(txInputHash)
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2sh.Script
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2sh.Script)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	witOpts := &signOpts{pubkeyScript: p2wpkh.WitnessScript}
	if err := signTransaction(p, prvKeys, scripts, true, witOpts); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedTxP2WPKH(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be a native segwit input, thus
	* locked by a p2wpkh script, while the outputs will be a legacy p2sh for the
	* receiver and the same segwit p2wpkh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	**/

	// Generate sender random key pair.
	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wpkh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedTxP2SH_P2MS(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be a legacy input locked by a
	* p2sh(p2ms) multisig script, while the outputs will be a legacy p2pkh for
	* the receiver and the same legacy p2sh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	**/

	// Generate sender random key pair.
	alice, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	alicePubkey := alice.PubKey()

	bob, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	bobPubkey := bob.PubKey()
	pubkeys := []*btcec.PublicKey{alicePubkey, bobPubkey}

	p2sh, _ := payment.FromPublicKeys(pubkeys, 2, &network.Regtest, nil)
	address, _ := p2sh.ScriptHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2sh.Script
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	prevTxHex, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	prevTx, _ := transaction.NewTxFromHex(prevTxHex)
	if err := updater.AddInNonWitnessUtxo(prevTx, 0); err != nil {
		t.Fatal(err)
	}

	alicePrvKeys := []*btcec.PrivateKey{alice}
	scripts := [][]byte{p2sh.Redeem.Script}
	opts := &signOpts{pubkeyScript: p2sh.Redeem.Script}
	if err := signTransaction(p, alicePrvKeys, scripts, false, opts); err != nil {
		t.Fatal(err)
	}

	bobPrvKeys := []*btcec.PrivateKey{bob}
	if err := signTransaction(p, bobPrvKeys, scripts, false, opts); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedTxP2WSH_P2MS(t *testing.T) {
	/**
	* This test attempts to broadcast a transaction composed by 1 input and 3
	* outputs. The input of the transaction will be a native segwit input locked
	* by a p2wsh script, while the outputs will be a legacy p2pkh for the
	* receiver and the same segwit p2wsh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicits.
	**/

	// Generate sender random key pair.
	alice, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	alicePubkey := alice.PubKey()

	bob, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	bobPubkey := bob.PubKey()
	pubkeys := []*btcec.PublicKey{alicePubkey, bobPubkey}

	p2wsh, _ := payment.FromPublicKeys(pubkeys, 2, &network.Regtest, nil)
	address, _ := p2wsh.WitnessScriptHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript, _ := hex.DecodeString("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wsh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wsh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	scripts := [][]byte{p2wsh.Redeem.Script}
	opts := &signOpts{script: p2wsh.Redeem.Script}
	alicePrvKeys := []*btcec.PrivateKey{alice}
	if err := signTransaction(p, alicePrvKeys, scripts, true, opts); err != nil {
		t.Fatal(err)
	}
	bobPrvKeys := []*btcec.PrivateKey{bob}
	if err := signTransaction(p, bobPrvKeys, scripts, true, opts); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastUnblindedIssuanceTx(t *testing.T) {
	/**
	* This test attempts to broadcast an issuance transaction composed by 1
	* P2WPKH input and 3 outputs. The input of the transaction will contain a new
	* unblinded asset issuance with a defined reissuance token. The outputs will
	* be a p2wpkh for both the asset and the relative token and another p2wpkh
	* for the change (same of the sender for simplicity). A 4th unblinded output
	* is for the fees, that in Elements side chains are explicits.
	**/

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(99999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(500)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{changeOutput, feeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	arg := AddIssuanceArgs{
		Precision: 0,
		Contract: &transaction.IssuanceContract{
			Name:      "Test",
			Ticker:    "TST",
			Version:   0,
			Precision: 0,
			Entity: transaction.IssuanceEntity{
				Domain: "test.io",
			},
		},
		AssetAmount:  1000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
	}
	if err := updater.AddIssuance(arg); err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wpkh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastBlindedTx(t *testing.T) {
	/**
	* This test attempts to broadcast a confidential transaction composed by 1
	* P2WPKH unbinded input and 2 blinded outputs. The outputs will be a
	* confidential p2sh for the receiver and a confidential p2wpkh for the
	* change. A 3rd unblinded output is for the fees with empty script.
	**/

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript := h2b("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	// Create a new pset with all the outputs that need to be blinded first
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wpkh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	//blind outputs
	inBlindingPrvKeys := [][]byte{{}}
	outBlindingPrvKeys := make([][]byte, 2)
	for i := range outBlindingPrvKeys {
		pk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Fatal(err)
		}
		outBlindingPrvKeys[i] = pk.Serialize()
	}

	if err := blindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	// Add the unblinded outputs now, that's only the fee output in this case
	addFeesToTransaction(p, 500)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastBlindedTxWithBlindedInput(t *testing.T) {
	/**
	* This test attempts to broadcast a confidential transaction composed by 1
	* P2WPKH confidential input and 2 confidential outputs. The outputs will be a
	* confidetial p2sh for the receiver and a confidential p2wpkh for the change.
	* The 3rd output is for the fees, that in Elements side chains are explicit.
	**/

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	blindingPrivateKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindingPublicKey := blindingPrivateKey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindingPublicKey)
	confidentialAddress, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(confidentialAddress); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(confidentialAddress)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 3 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	receiverValue, _ := elementsutil.SatoshiToElementsValue(60000000)
	receiverScript := h2b("76a91439397080b51ef22c59bd7469afacffbeec0da12e88ac")
	receiverOutput := transaction.NewTxOutput(lbtc, receiverValue, receiverScript)

	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(39999500)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{receiverOutput, changeOutput}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Add sighash type and witness utxo to the partial input.
	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	txHex, err := fetchTx(utxos[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := transaction.NewTxFromHex(txHex)
	valueCommitment := h2b(utxos[0]["valuecommitment"].(string))
	assetCommitment := h2b(utxos[0]["assetcommitment"].(string))
	witnessUtxo := &transaction.TxOutput{
		Asset:           assetCommitment,
		Value:           valueCommitment,
		Script:          p2wpkh.WitnessScript,
		Nonce:           tx.Outputs[txInputIndex].Nonce,
		RangeProof:      tx.Outputs[txInputIndex].RangeProof,
		SurjectionProof: tx.Outputs[txInputIndex].SurjectionProof,
	}

	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	//blind outputs
	inBlindingPrvKeys := [][]byte{blindingPrivateKey.Serialize()}
	outBlindingPrvKeys := make([][]byte, 2)
	for i := range outBlindingPrvKeys {
		pk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Fatal(err)
		}
		outBlindingPrvKeys[i] = pk.Serialize()
	}

	if err := blindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	addFeesToTransaction(p, 500)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastIssuanceTxWithBlindedOutput(t *testing.T) {
	/**
	* This test attempts to broadcast a confidential issuance transaction
	* composed by 1 P2WPKH unblinded  input and 3 confidentialoutputs. The
	* outputs will be a confidetial p2wpkh for both the issued asset and the
	* relative token, and another confidential p2wpkh for the change. A 4th
	* unblinded output is for the fees, with empty script.
	**/

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()
	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, nil)
	address, _ := p2wpkh.WitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxos, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 2 outputs.
	txInputHash := elementsutil.ReverseBytes(h2b(utxos[0]["txid"].(string)))
	txInputIndex := uint32(utxos[0]["vout"].(float64))
	txInput := transaction.NewTxInput(txInputHash, txInputIndex)

	// Create a new pset.
	inputs := []*transaction.TxInput{txInput}
	outputs := []*transaction.TxOutput{}
	p, err := New(inputs, outputs, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater, err := NewUpdater(p)
	if err != nil {
		t.Fatal(err)
	}

	arg := AddIssuanceArgs{
		Precision: 0,
		Contract: &transaction.IssuanceContract{
			Name:      "Test",
			Ticker:    "TST",
			Version:   0,
			Precision: 0,
			Entity: transaction.IssuanceEntity{
				Domain: "test.io",
			},
		},
		AssetAmount:  1000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
	}
	if err := updater.AddIssuance(arg); err != nil {
		t.Fatal(err)
	}

	witValue, _ := elementsutil.SatoshiToElementsValue(uint64(utxos[0]["value"].(float64)))
	witnessUtxo := transaction.NewTxOutput(lbtc, witValue, p2wpkh.WitnessScript)
	if err := updater.AddInWitnessUtxo(witnessUtxo, 0); err != nil {
		t.Fatal(err)
	}

	// Add change and fees
	changeScript := p2wpkh.WitnessScript
	changeValue, _ := elementsutil.SatoshiToElementsValue(99996000)
	changeOutput := transaction.NewTxOutput(lbtc, changeValue, changeScript)
	updater.AddOutput(changeOutput)

	//blind outputs
	inBlindingPrvKeys := [][]byte{{}}
	outBlindingPrvKeys := make([][]byte, 2)
	for i := range outBlindingPrvKeys {
		pk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Fatal(err)
		}
		outBlindingPrvKeys[i] = pk.Serialize()
	}
	outBlindingPrvKeys = append(
		[][]byte{outBlindingPrvKeys[0]},
		outBlindingPrvKeys...,
	)

	if err := blindTransaction(
		p,
		inBlindingPrvKeys,
		outBlindingPrvKeys,
		nil,
	); err != nil {
		t.Fatal(err)
	}

	addFeesToTransaction(p, 4000)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(p, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(p); err != nil {
		t.Fatal(err)
	}
}

func TestBroadcastBlindedIssuanceAndReIssuanceTx(t *testing.T) {
	/**
	* This test attempts to broadcast a confidential issuance transaction
	* and then a reissuance transaction composed by 2 confidential P2wWPKH inputs
	* and 3 confidential P2WPKH outputs. The outputs will be a confidetial p2wpkh
	* for both the reissued asset and the relative reissunce token, and another
	* confidential p2wpkh for the change for paying the network fees. A 4th
	* unblinded output is for the fees, with empty script.
	**/

	privkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	pubkey := privkey.PubKey()

	blindPrivkey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		t.Fatal(err)
	}
	blindPubkey := blindPrivkey.PubKey()

	p2wpkh := payment.FromPublicKey(pubkey, &network.Regtest, blindPubkey)
	address, _ := p2wpkh.ConfidentialWitnessPubKeyHash()

	// Fund sender address.
	if _, err := faucet(address); err != nil {
		t.Fatal(err)
	}

	// Retrieve sender utxos.
	utxosForIssuanceTx, err := unspents(address)
	if err != nil {
		t.Fatal(err)
	}

	// The transaction will have 1 input and 2 outputs.
	txInputHashForIssuanceTx := elementsutil.ReverseBytes(
		h2b(utxosForIssuanceTx[0]["txid"].(string)),
	)
	txInputIndexForIssuanceTx := uint32(utxosForIssuanceTx[0]["vout"].(float64))
	txInputForIssuanceTx := transaction.NewTxInput(
		txInputHashForIssuanceTx,
		txInputIndexForIssuanceTx,
	)

	// Create a new pset.
	inputsForIssuanceTx := []*transaction.TxInput{txInputForIssuanceTx}
	outputsForIssuanceTx := []*transaction.TxOutput{}
	issuancePset, err := New(inputsForIssuanceTx, outputsForIssuanceTx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater, err := NewUpdater(issuancePset)
	if err != nil {
		t.Fatal(err)
	}

	issuanceArgs := AddIssuanceArgs{
		Precision:    0,
		AssetAmount:  2000,
		TokenAmount:  1,
		AssetAddress: address,
		TokenAddress: address,
	}
	if err := updater.AddIssuance(issuanceArgs); err != nil {
		t.Fatal(err)
	}

	txHex, err := fetchTx(utxosForIssuanceTx[0]["txid"].(string))
	if err != nil {
		t.Fatal(err)
	}
	tx, _ := transaction.NewTxFromHex(txHex)
	assetCommitmentForIssuanceTx := h2b(utxosForIssuanceTx[0]["assetcommitment"].(string))
	valueCommitmentForIssuanceTx := h2b(utxosForIssuanceTx[0]["valuecommitment"].(string))
	witnessUtxoForIssuanceTx := &transaction.TxOutput{
		Asset:           assetCommitmentForIssuanceTx,
		Value:           valueCommitmentForIssuanceTx,
		Script:          p2wpkh.WitnessScript,
		Nonce:           tx.Outputs[txInputIndexForIssuanceTx].Nonce,
		RangeProof:      tx.Outputs[txInputIndexForIssuanceTx].RangeProof,
		SurjectionProof: tx.Outputs[txInputIndexForIssuanceTx].SurjectionProof,
	}
	if err := updater.AddInWitnessUtxo(witnessUtxoForIssuanceTx, 0); err != nil {
		t.Fatal(err)
	}

	// Add change and fees
	changeScriptForIssuanceTx := p2wpkh.WitnessScript
	changeValueForIssuanceTx, _ := elementsutil.SatoshiToElementsValue(99996000)
	changeOutputForIssuanceTx := transaction.NewTxOutput(
		lbtc,
		changeValueForIssuanceTx,
		changeScriptForIssuanceTx,
	)
	updater.AddOutput(changeOutputForIssuanceTx)

	//blind outputs
	inBlindingPrvKeysForIssuance := [][]byte{blindPrivkey.Serialize()}
	outBlindingPrvKeysForIssuance := make([][]byte, 2)
	for i := range outBlindingPrvKeysForIssuance {
		pk, err := btcec.NewPrivateKey(btcec.S256())
		if err != nil {
			t.Fatal(err)
		}
		outBlindingPrvKeysForIssuance[i] = pk.Serialize()
	}
	outBlindingPrvKeysForIssuance = append(
		[][]byte{outBlindingPrvKeysForIssuance[0]},
		outBlindingPrvKeysForIssuance...,
	)

	issuanceBlindPrvKeys := []IssuanceBlindingPrivateKeys{
		{
			AssetKey: outBlindingPrvKeysForIssuance[1],
			TokenKey: outBlindingPrvKeysForIssuance[2],
		},
	}

	if err := blindTransaction(
		issuancePset,
		inBlindingPrvKeysForIssuance,
		outBlindingPrvKeysForIssuance,
		issuanceBlindPrvKeys,
	); err != nil {
		t.Fatal(err)
	}

	addFeesToTransaction(issuancePset, 4000)

	prvKeys := []*btcec.PrivateKey{privkey}
	scripts := [][]byte{p2wpkh.Script}
	if err := signTransaction(issuancePset, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	issuanceTxID, err := broadcastTransaction(issuancePset)
	if err != nil {
		t.Fatal(err)
	}

	// RE-ISSUANCE

	// we need to unblind the token output of the issuance tx to get its
	// asset blinding factor that will be used as reissuance's blinding nonce
	unblinded, err := confidential.UnblindOutputWithKey(
		issuancePset.UnsignedTx.Outputs[1],
		outBlindingPrvKeysForIssuance[1],
	)
	if err != nil {
		t.Fatal(err)
	}

	// lbtc input for paying network fees
	txInputHashForReissuanceTx := elementsutil.ReverseBytes(h2b(issuanceTxID))
	// we know that the third output of the issuance tx is the lbtc change
	txInputIndexForReissuanceTx := uint32(2)
	txInputForReissuanceTx := transaction.NewTxInput(
		txInputHashForReissuanceTx,
		txInputIndexForReissuanceTx,
	)

	inputsForReissuanceTx := []*transaction.TxInput{txInputForReissuanceTx}
	outputsForReissuanceTx := []*transaction.TxOutput{}
	reissuancePset, err := New(inputsForReissuanceTx, outputsForReissuanceTx, 2, 0)
	if err != nil {
		t.Fatal(err)
	}

	updater, err = NewUpdater(reissuancePset)
	if err != nil {
		t.Fatal(err)
	}

	if err := updater.AddInWitnessUtxo(issuancePset.UnsignedTx.Outputs[2], 0); err != nil {
		t.Fatal(err)
	}

	issuance, err := transaction.NewTxIssuanceFromInput(
		issuancePset.UnsignedTx.Inputs[0],
	)
	if err != nil {
		t.Fatal(err)
	}
	entropy := b2h(elementsutil.ReverseBytes(issuance.TxIssuance.AssetEntropy))

	reissuanceArgs := AddReissuanceArgs{
		PrevOutHash:    issuanceTxID,
		PrevOutIndex:   uint32(1),
		PrevOutBlinder: unblinded.AssetBlindingFactor,
		Entropy:        entropy,
		AssetAmount:    3300,
		TokenAmount:    1,
		AssetAddress:   address,
		TokenAddress:   address,
		WitnessUtxo:    issuancePset.UnsignedTx.Outputs[1],
	}

	if err := updater.AddReissuance(reissuanceArgs); err != nil {
		t.Fatal(err)
	}

	// Add change and fees
	changeScriptForReissuanceTx := p2wpkh.WitnessScript
	changeValueForReissuanceTx, _ := elementsutil.SatoshiToElementsValue(99991000)
	changeOutputForReissuanceTx := transaction.NewTxOutput(
		lbtc,
		changeValueForReissuanceTx,
		changeScriptForReissuanceTx,
	)
	updater.AddOutput(changeOutputForReissuanceTx)

	inBlindPrvKeysForReissuance := [][]byte{outBlindingPrvKeysForIssuance[2], outBlindingPrvKeysForIssuance[1]}
	outBlindPrvKeysForReissuance := outBlindingPrvKeysForIssuance
	reissuanceBlindingPrivateKeys := append([]IssuanceBlindingPrivateKeys{{}}, issuanceBlindPrvKeys...)

	if err := blindTransaction(
		reissuancePset,
		inBlindPrvKeysForReissuance,
		outBlindPrvKeysForReissuance,
		reissuanceBlindingPrivateKeys,
	); err != nil {
		t.Fatal(err)
	}

	addFeesToTransaction(reissuancePset, 5000)

	prvKeys = append(prvKeys, privkey)
	scripts = append(scripts, p2wpkh.Script)
	if err := signTransaction(reissuancePset, prvKeys, scripts, true, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := broadcastTransaction(reissuancePset); err != nil {
		t.Fatal(err)
	}
}

func addFeesToTransaction(p *Pset, feeAmount uint64) {
	updater, _ := NewUpdater(p)
	feeScript := []byte{}
	feeValue, _ := elementsutil.SatoshiToElementsValue(feeAmount)
	feeOutput := transaction.NewTxOutput(lbtc, feeValue, feeScript)
	updater.AddOutput(feeOutput)
}

func blindTransaction(
	p *Pset,
	inBlindKeys, outBlindKeys [][]byte,
	issuanceBlindKeys []IssuanceBlindingPrivateKeys,
) error {
	outBlindPubKeys := make([][]byte, 0, len(outBlindKeys))
	for _, k := range outBlindKeys {
		_, pubkey := btcec.PrivKeyFromBytes(btcec.S256(), k)
		outBlindPubKeys = append(outBlindPubKeys, pubkey.SerializeCompressed())
	}

	psetBase64, err := p.ToBase64()
	if err != nil {
		return err
	}

	for {
		ptx, _ := NewPsetFromBase64(psetBase64)
		blinder, err := NewBlinder(
			ptx,
			inBlindKeys,
			outBlindPubKeys,
			issuanceBlindKeys,
			nil,
		)
		if err != nil {
			return err
		}

		for {
			if err := blinder.Blind(); err != nil {
				if err != ErrGenerateSurjectionProof {
					return err
				}
				continue
			}
			break
		}

		if VerifyBlinding(ptx, inBlindKeys, outBlindKeys, issuanceBlindKeys) {
			*p = *ptx
			break
		}
	}
	return nil
}

type signOpts struct {
	pubkeyScript []byte
	script       []byte
}

func signTransaction(
	p *Pset,
	privKeys []*btcec.PrivateKey,
	scripts [][]byte,
	forWitness bool,
	opts *signOpts,
) error {
	updater, err := NewUpdater(p)
	if err != nil {
		return err
	}

	for i, in := range p.Inputs {
		if err := updater.AddInSighashType(txscript.SigHashAll, i); err != nil {
			return err
		}

		var prevout *transaction.TxOutput
		if in.WitnessUtxo != nil {
			prevout = in.WitnessUtxo
		} else {
			prevout = in.NonWitnessUtxo.Outputs[p.UnsignedTx.Inputs[i].Index]
		}
		prvkey := privKeys[i]
		pubkey := prvkey.PubKey()
		script := scripts[i]

		var sigHash [32]byte
		if forWitness {
			sigHash = p.UnsignedTx.HashForWitnessV0(
				i,
				script,
				prevout.Value,
				txscript.SigHashAll,
			)
		} else {
			sigHash, err = p.UnsignedTx.HashForSignature(i, script, txscript.SigHashAll)
			if err != nil {
				return err
			}
		}

		sig, err := prvkey.Sign(sigHash[:])
		if err != nil {
			return err
		}
		sigWithHashType := append(sig.Serialize(), byte(txscript.SigHashAll))

		var witPubkeyScript []byte
		var witScript []byte
		if opts != nil {
			witPubkeyScript = opts.pubkeyScript
			witScript = opts.script
		}

		if _, err := updater.Sign(
			i,
			sigWithHashType,
			pubkey.SerializeCompressed(),
			witPubkeyScript,
			witScript,
		); err != nil {
			return err
		}
	}

	valid, err := p.ValidateAllSignatures()
	if err != nil {
		return err
	}
	if !valid {
		return errors.New("invalid signatures")
	}

	return nil
}

func broadcastTransaction(p *Pset) (string, error) {
	// Finalize the partial transaction.
	if err := FinalizeAll(p); err != nil {
		return "", err
	}
	// Extract the final signed transaction from the Pset wrapper.
	finalTx, err := Extract(p)
	if err != nil {
		return "", err
	}
	// Serialize the transaction and try to broadcast.
	txHex, err := finalTx.ToHex()
	if err != nil {
		return "", err
	}

	return broadcast(txHex)
}

func faucet(address string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/faucet", baseUrl)
	payload := map[string]string{"address": address}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
		return "", fmt.Errorf("cannot fund address with faucet: %s", res)
	}

	respBody := map[string]string{}
	if err := json.Unmarshal(data, &respBody); err != nil {
		return "", err
	}
	return respBody["txId"], nil
}

func mint(address string, quantity int, name string, ticker string) (string, string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", "", err
	}

	url := fmt.Sprintf("%s/mint", baseUrl)
	payload := map[string]interface{}{
		"address":  address,
		"quantity": quantity,
		"name":     name,
		"ticker":   ticker,
	}
	body, _ := json.Marshal(payload)

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	if err != nil {
		return "", "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	if res := string(data); len(res) <= 0 || strings.Contains(res, "sendtoaddress") {
		return "", "", fmt.Errorf("cannot fund address with minted asset: %s", res)
	}

	respBody := map[string]interface{}{}
	if err := json.Unmarshal(data, &respBody); err != nil {
		return "", "", err
	}
	return respBody["txId"].(string), respBody["asset"].(string), nil
}

func unspents(address string) ([]map[string]interface{}, error) {
	getUtxos := func(address string) ([]interface{}, error) {
		baseUrl, err := apiBaseUrl()
		if err != nil {
			return nil, err
		}
		url := fmt.Sprintf("%s/address/%s/utxo", baseUrl, address)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		data, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var respBody interface{}
		if err := json.Unmarshal(data, &respBody); err != nil {
			return nil, err
		}
		return respBody.([]interface{}), nil
	}

	utxos := []map[string]interface{}{}
	for len(utxos) <= 0 {
		time.Sleep(1 * time.Second)
		u, err := getUtxos(address)
		if err != nil {
			return nil, err
		}
		for _, unspent := range u {
			utxo := unspent.(map[string]interface{})
			utxos = append(utxos, utxo)
		}
	}

	return utxos, nil
}

func broadcast(txHex string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx", baseUrl)

	resp, err := http.Post(url, "text/plain", strings.NewReader(txHex))
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	res := string(data)
	if len(res) <= 0 || strings.Contains(res, "sendrawtransaction") {
		return "", fmt.Errorf("failed to broadcast tx: %s", res)
	}
	return res, nil
}

func fetchTx(txId string) (string, error) {
	baseUrl, err := apiBaseUrl()
	if err != nil {
		return "", err
	}
	url := fmt.Sprintf("%s/tx/%s/hex", baseUrl, txId)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func apiBaseUrl() (string, error) {
	u, ok := os.LookupEnv("API_URL")
	if !ok {
		return "", errors.New("API_URL environment variable is not set")
	}
	return u, nil
}

func b2h(buf []byte) string {
	return hex.EncodeToString(buf)
}

func h2b(str string) []byte {
	buf, _ := hex.DecodeString(str)
	return buf
}
