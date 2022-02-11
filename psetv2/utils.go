package psetv2

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil/psbt"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/transaction"
)

func writeTxOut(txout *transaction.TxOutput) ([]byte, error) {
	s := bufferutil.NewSerializer(nil)

	if err := s.WriteSlice(txout.Asset); err != nil {
		return nil, err
	}
	if err := s.WriteSlice(txout.Value); err != nil {
		return nil, err
	}
	if err := s.WriteSlice(txout.Nonce); err != nil {
		return nil, err
	}
	if err := s.WriteVarSlice(txout.Script); err != nil {
		return nil, err
	}
	if txout.IsConfidential() {
		if err := s.WriteVarSlice(txout.SurjectionProof); err != nil {
			return nil, err
		}
		if err := s.WriteVarSlice(txout.RangeProof); err != nil {
			return nil, err
		}
	}
	return s.Bytes(), nil
}

func readTxOut(txout []byte) (*transaction.TxOutput, error) {
	if len(txout) < 45 {
		return nil, ErrInvalidPsbtFormat
	}
	d := bufferutil.NewDeserializer(bytes.NewBuffer(txout))
	asset, err := d.ReadElementsAsset()
	if err != nil {
		return nil, err
	}
	value, err := d.ReadElementsValue()
	if err != nil {
		return nil, err
	}
	nonce, err := d.ReadElementsNonce()
	if err != nil {
		return nil, err
	}
	script, err := d.ReadVarSlice()
	if err != nil {
		return nil, err
	}
	surjectionProof := make([]byte, 0)
	rangeProof := make([]byte, 0)
	// nonce for unconf outputs is 0x00!
	if len(nonce) > 1 {
		surjectionProof, err = d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
		rangeProof, err = d.ReadVarSlice()
		if err != nil {
			return nil, err
		}
	}
	return &transaction.TxOutput{
		Asset:           asset,
		Value:           value,
		Script:          script,
		Nonce:           nonce,
		RangeProof:      rangeProof,
		SurjectionProof: surjectionProof,
	}, nil
}

func isAssetExplicit(asset []byte) bool {
	return len(asset) == 33 && asset[0] == 1
}

// extractKeyOrderFromScript is a utility function to extract an ordered list
// of signatures, given a serialized script (redeemscript or witness script), a
// list of pubkeys and the signatures corresponding to those pubkeys. This
// function is used to ensure that the signatures will be embedded in the final
// scriptSig or scriptWitness in the correct order.
func extractKeyOrderFromScript(script []byte, expectedPubkeys [][]byte,
	sigs [][]byte) ([][]byte, error) {

	// If this isn't a proper finalized multi-sig script, then we can't
	// proceed.
	if !checkIsMultiSigScript(expectedPubkeys, sigs, script) {
		return nil, psbt.ErrUnsupportedScriptType
	}

	// Arrange the pubkeys and sigs into a slice of format:
	//   * [[pub,sig], [pub,sig],..]
	type sigWithPub struct {
		pubKey []byte
		sig    []byte
	}
	var pubsSigs []sigWithPub
	for i, pub := range expectedPubkeys {
		pubsSigs = append(pubsSigs, sigWithPub{
			pubKey: pub,
			sig:    sigs[i],
		})
	}

	// Now that we have the set of (pubkey, sig) pairs, we'll construct a
	// position map that we can use to swap the order in the slice above to
	// match how things are laid out in the script.
	type positionEntry struct {
		index int
		value sigWithPub
	}
	var positionMap []positionEntry

	// For each pubkey in our pubsSigs slice, we'll now construct a proper
	// positionMap entry, based on _where_ in the script the pubkey first
	// appears.
	for _, p := range pubsSigs {
		pos := bytes.Index(script, p.pubKey)
		if pos < 0 {
			return nil, fmt.Errorf("script does not contain pubkeys")
		}

		positionMap = append(positionMap, positionEntry{
			index: pos,
			value: p,
		})
	}

	// Now that we have the position map full populated, we'll use the
	// index data to properly sort the entries in the map based on where
	// they appear in the script.
	sort.Slice(positionMap, func(i, j int) bool {
		return positionMap[i].index < positionMap[j].index
	})

	// Finally, we can simply iterate through the position map in order to
	// extract the proper signature ordering.
	sortedSigs := make([][]byte, 0, len(positionMap))
	for _, x := range positionMap {
		sortedSigs = append(sortedSigs, x.value.sig)
	}

	return sortedSigs, nil
}

// checkIsMultisigScript is a utility function to check whether a given
// redeemscript fits the standard multisig template used in all P2SH based
// multisig, given a set of pubkeys for redemption.
func checkIsMultiSigScript(pubKeys [][]byte, sigs [][]byte,
	script []byte) bool {

	// First insist that the script type is multisig.
	if txscript.GetScriptClass(script) != txscript.MultiSigTy {
		return false
	}

	// Inspect the script to ensure that the number of sigs and pubkeys is
	// correct
	_, numSigs, err := txscript.CalcMultiSigStats(script)
	if err != nil {
		return false
	}

	// If the number of sigs provided, doesn't match the number of required
	// pubkeys, then we can't proceed as we're not yet final.
	if numSigs != len(pubKeys) || numSigs != len(sigs) {
		return false
	}

	return true
}

// writePKHWitness writes a witness for a p2wkh spending input
func writePKHWitness(sig []byte, pub []byte) ([]byte, error) {
	witnessItems := [][]byte{sig, pub}

	return writeTxWitness(witnessItems)
}

// writeTxWitness is a A utility function due to non-exported witness
// serialization (writeTxWitness encodes the bitcoin protocol encoding for a
// transaction input's witness into w).
func writeTxWitness(wit [][]byte) ([]byte, error) {
	s := bufferutil.NewSerializer(nil)

	if err := s.WriteVarInt(uint64(len(wit))); err != nil {
		return nil, err
	}

	for _, item := range wit {
		err := s.WriteVarSlice(item)
		if err != nil {
			return nil, err
		}
	}
	return s.Bytes(), nil
}

// getMultisigScriptWitness creates a full psbt serialized Witness field for
// the transaction, given the public keys and signatures to be appended. This
// function will only accept witnessScripts of the type M of N multisig. This
// is used for both p2wsh and nested p2wsh multisig cases.
func getMultisigScriptWitness(witnessScript []byte, pubKeys [][]byte,
	sigs [][]byte) ([]byte, error) {

	// First using the script as a guide, we'll properly order the sigs
	// according to how their corresponding pubkeys appear in the
	// witnessScript.
	orderedSigs, err := extractKeyOrderFromScript(
		witnessScript, pubKeys, sigs,
	)
	if err != nil {
		return nil, err
	}

	// Now that we know the proper order, we'll append each of the
	// signatures into a new witness stack, then top it off with the
	// witness script at the end, prepending the nil as we need the extra
	// pop..
	witnessElements := make(transaction.TxWitness, 0, len(sigs)+2)
	witnessElements = append(witnessElements, nil)
	for _, os := range orderedSigs {
		witnessElements = append(witnessElements, os)
	}
	witnessElements = append(witnessElements, witnessScript)

	// Now that we have the full witness stack, we'll serialize it in the
	// expected format, and return the final bytes.
	return writeTxWitness(witnessElements)
}

// checkSigHashFlags compares the sighash flag byte on a signature with the
// value expected according to any InputSighashType field in this section of
// the PSBT, and returns true if they match, false otherwise.
// If no SighashType field exists, it is assumed to be SIGHASH_ALL.
//
// TODO(waxwing): sighash type not restricted to one byte in future?
func checkSigHashFlags(sig []byte, input Input) bool {
	expectedSighashType := txscript.SigHashAll
	if input.SigHashType != 0 {
		expectedSighashType = input.SigHashType
	}

	return expectedSighashType == txscript.SigHashType(sig[len(sig)-1])
}

func min(x, y uint32) uint32 {
	if x < y {
		return x
	}
	return y
}

func max(x, y uint32) uint32 {
	if x > y {
		return x
	}
	return y
}
