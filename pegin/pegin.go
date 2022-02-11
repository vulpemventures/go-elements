package pegin

import (
	"bytes"
	"crypto/sha256"
	"errors"

	"github.com/btcsuite/btcd/wire"
	"github.com/vulpemventures/go-elements/block"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/transaction"

	"github.com/btcsuite/btcutil"

	"github.com/btcsuite/btcd/txscript"

	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/payment"

	"github.com/btcsuite/btcd/chaincfg"

	"github.com/vulpemventures/go-elements/address"

	"github.com/btcsuite/btcd/btcec"
)

type AddressInfo struct {
	ClaimScript      string
	MainChainAddress string
}

// MainChainAddress creates btc address to which BTC amount is to be sent that is
// to be pegged in Liquid network
func MainChainAddress(
	contract []byte,
	btcNetwork *chaincfg.Params,
	isDynaFedEnabled bool,
	fedpegScript []byte,
) (string, error) {
	pops, err := address.ParseScript(fedpegScript)
	if err != nil {
		return "", err
	}

	var mainChainAddress string
	if !isDynaFedEnabled || address.IsScriptHash(pops) {
		//P2SH - P2WSH(P2CH)
		witnessScriptHash := sha256.Sum256(contract)
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0).AddData(witnessScriptHash[:])
		script, err := builder.Script()
		if err != nil {
			return "", err
		}
		ps2h, err := btcutil.NewAddressScriptHash(script, btcNetwork)
		if err != nil {
			return "", err
		}
		mainChainAddress = ps2h.String()
	} else {
		//P2WSH - P2CH
		witnessScriptHash := sha256.Sum256(contract)
		p2wsh, err := btcutil.NewAddressWitnessScriptHash(
			witnessScriptHash[:],
			btcNetwork,
		)
		if err != nil {
			return "", err
		}
		mainChainAddress = p2wsh.String()
	}

	return mainChainAddress, nil
}

// ClaimWitnessScript returns claim script that is to be used to calculate contract
// (pegincontract.Calculate) and craft raw pegin transaction (pegin.Claim)
func ClaimWitnessScript(
	publicKeyBytes []byte,
	net *network.Network,
) ([]byte, error) {

	publicKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return nil, err
	}

	p2wpkh := payment.FromPublicKey(
		publicKey,
		net,
		nil,
	)
	return p2wpkh.WitnessScript, nil
}

// Claim crafts raw claim pegin transaction which is to be signed and broadcated
// to network
func Claim(
	btcNetwork *chaincfg.Params,
	isDynaFedEnabled bool,
	peggedAsset []byte,
	parentGenesisBlockHash []byte,
	fedpegScript []byte,
	contract []byte,
	btcTx []byte,
	btcTxOutProof []byte,
	claimScript []byte,
	milisatsPerByte float64,
) (*transaction.Transaction, error) {
	claimTx := transaction.NewTx(2)

	input, amount, err := createPeginInput(
		btcTx,
		peggedAsset,
		parentGenesisBlockHash,
		claimScript,
		btcTxOutProof,
		fedpegScript,
		contract,
		btcNetwork,
		isDynaFedEnabled,
	)
	if err != nil {
		return nil, err
	}

	startValue, err := elementsutil.ValueToBytes(uint64(amount))
	if err != nil {
		return nil, err
	}
	receiverOutput := transaction.NewTxOutput(peggedAsset, startValue, claimScript)

	dummyFeeValue, _ := elementsutil.ValueToBytes(uint64(0))
	feeOutput := transaction.NewTxOutput(peggedAsset, dummyFeeValue, []byte{})

	claimTx.AddInput(input)
	claimTx.AddOutput(receiverOutput)
	claimTx.AddOutput(feeOutput)

	txSize := claimTx.VirtualSize()
	feeValue := uint64(float64(txSize) * milisatsPerByte)

	finalValue := uint64(amount) - feeValue
	finalValueElements, err := elementsutil.ValueToBytes(finalValue)
	if err != nil {
		return nil, err
	}

	feeValueElements, err := elementsutil.ValueToBytes(feeValue)
	if err != nil {
		return nil, err
	}

	claimTx.Outputs[0].Value = finalValueElements
	claimTx.Outputs[1].Value = feeValueElements

	return claimTx, nil
}

type FedpegInfo struct {
	FedpegScript  []byte
	FedpegProgram []byte
}

func createPeginInput(
	btcTx []byte,
	peggedAsset []byte,
	parentGenesisBlockHash []byte,
	claimScript []byte,
	btcTxOutProof []byte,
	fedpegScript []byte,
	contract []byte,
	btcNetwork *chaincfg.Params,
	isDynaFedEnabled bool,
) (*transaction.TxInput, int64, error) {
	merkleBlock, err := block.NewMerkleBlockFromBuffer(
		bytes.NewBuffer(btcTxOutProof),
	)
	if err != nil {
		return nil, 0, err
	}

	hashMerkleRoot, matchedHashes, err := merkleBlock.ExtractMatches()
	if err != nil {
		return nil, 0, err
	}

	if !merkleBlock.BlockHeader.MerkleRoot.IsEqual(hashMerkleRoot) {
		return nil, 0, errors.New("invalid tx out proof")
	}

	var tx wire.MsgTx
	buff := bytes.NewReader(btcTx)
	err = tx.BtcDecode(buff, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return nil, 0, err
	}

	h := tx.TxHash()
	if len(matchedHashes) != 1 || !h.IsEqual(&matchedHashes[0]) {
		return nil, 0, errors.New(
			"the txoutproof must contain bitcoinTx and only bitcoinTx",
		)
	}

	//validate claim script against claim_script/contract
	outIndex, amount, err := GetPeginTxOutIndexAndAmount(
		btcTx,
		fedpegScript,
		contract,
		btcNetwork,
		isDynaFedEnabled,
	)
	if err != nil {
		return nil, 0, err
	}

	peginWitness, err := createPeginWitness(
		amount,
		peggedAsset,
		parentGenesisBlockHash,
		claimScript,
		btcTx,
		btcTxOutProof,
	)
	if err != nil {
		return nil, 0, err
	}

	input := transaction.NewTxInput(matchedHashes[0].CloneBytes(), outIndex)
	input.IsPegin = true
	input.PeginWitness = peginWitness

	return input, amount, nil
}

func GetPeginTxOutIndexAndAmount(
	btcTx []byte,
	fedpegScript []byte,
	contract []byte,
	btcNetwork *chaincfg.Params,
	isDynaFedEnabled bool,
) (uint32, int64, error) {
	pops, err := address.ParseScript(fedpegScript)
	if err != nil {
		return 0, 0, err
	}

	mainChainScript := []byte{}
	if !isDynaFedEnabled || address.IsScriptHash(pops) {
		witnessScriptHash := sha256.Sum256(contract)
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_0).AddData(witnessScriptHash[:])
		script, err := builder.Script()
		if err != nil {
			return 0, 0, err
		}
		ps2h, err := btcutil.NewAddressScriptHash(script, btcNetwork)
		if err != nil {
			return 0, 0, err
		}

		prefix := []byte{txscript.OP_HASH160, byte(len(ps2h.ScriptAddress()))}
		mainChainScript = append(prefix, ps2h.ScriptAddress()...)
		mainChainScript = append(mainChainScript, txscript.OP_EQUAL)
	} else {
		witnessScriptHash := sha256.Sum256(contract)
		p2wsh, err := btcutil.NewAddressWitnessScriptHash(
			witnessScriptHash[:],
			btcNetwork,
		)
		if err != nil {
			return 0, 0, err
		}
		mainChainScript = p2wsh.ScriptAddress()

		prefix := []byte{txscript.OP_0, byte(len(p2wsh.ScriptAddress()))}
		mainChainScript = append(prefix, p2wsh.ScriptAddress()...)
	}

	var tx wire.MsgTx
	buff := bytes.NewReader(btcTx)
	err = tx.BtcDecode(buff, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return 0, 0, err
	}

	var outIndex uint32 = 0
	var amount int64 = 0
	notFound := true
	for i, v := range tx.TxOut {
		if bytes.Equal(v.PkScript, mainChainScript) {
			notFound = false
			outIndex = uint32(i)
			amount = v.Value
		}
	}

	if notFound {
		return 0, 0, errors.New("cant find output in btc tx for provided contract")
	}

	return outIndex, amount, nil
}

func createPeginWitness(
	amount int64,
	peggedAsset []byte,
	parentGenesisBlockHash []byte,
	claimScript []byte,
	btcTx []byte,
	btcTxOutProof []byte,
) ([][]byte, error) {
	peginWitness := make([][]byte, 0)

	serialisedAmount, err := SerializeValue(amount)
	if err != nil {
		return nil, err
	}

	stripedTx, err := StripWitnessFromBtcTx(btcTx)
	if err != nil {
		return nil, err
	}

	peginWitness = append(peginWitness, serialisedAmount)
	peginWitness = append(peginWitness, peggedAsset[1:])
	peginWitness = append(peginWitness, elementsutil.ReverseBytes(parentGenesisBlockHash[:]))
	peginWitness = append(peginWitness, claimScript)
	peginWitness = append(peginWitness, stripedTx)
	peginWitness = append(peginWitness, btcTxOutProof)

	return peginWitness, nil
}

func SerializeValue(value int64) ([]byte, error) {
	valueBytes, err := elementsutil.ValueToBytes(uint64(value))
	if err != nil {
		return nil, err
	}
	revValueBytes := elementsutil.ReverseBytes(valueBytes[:])

	return revValueBytes[:len(revValueBytes)-1], nil
}

func StripWitnessFromBtcTx(btcTx []byte) ([]byte, error) {
	var tx wire.MsgTx
	buff := bytes.NewReader(btcTx)
	err := tx.BtcDecode(buff, wire.ProtocolVersion, wire.LatestEncoding)
	if err != nil {
		return nil, err
	}

	for i, v := range tx.TxIn {
		v.Witness = nil
		tx.TxIn[i] = v
	}

	stripedTx := bytes.NewBuffer(make([]byte, 0, tx.SerializeSize()))
	err = tx.Serialize(stripedTx)
	if err != nil {
		return nil, err
	}

	return stripedTx.Bytes(), nil
}
