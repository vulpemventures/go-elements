package psetv2

import (
	"bytes"

	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/transaction"
)

func writeTxOut(txout *transaction.TxOutput) ([]byte, error) {
	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return nil, err
	}
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
