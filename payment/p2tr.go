package payment

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	segwitVersion = byte(0x01)
)

// TaprootPaymentData is included in Payment struct to store Taproot-related data
type TaprootPaymentData struct {
	XOnlyTweakedKey    []byte
	XOnlyInternalKey   []byte
	RootScriptTreeHash *chainhash.Hash
	ScriptTree         *taproot.IndexedElementsTapScriptTree
}

// FromTweakedKey creates a P2TR payment from a tweaked output key
func FromTweakedKey(
	tweakedKey *btcec.PublicKey,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if tweakedKey == nil {
		return nil, errors.New("tweaked key can't be empty or nil")
	}

	if net == nil {
		net = &network.Liquid
	}

	return &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyTweakedKey: schnorr.SerializePubKey(tweakedKey),
		},
	}, nil
}

func FromTaprootScriptTreeHash(
	internalKey *btcec.PublicKey,
	rootHash *chainhash.Hash,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if internalKey == nil {
		return nil, errors.New("internal key can't be empty or nil")
	}

	if net == nil {
		net = &network.Liquid
	}

	return &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyInternalKey:   schnorr.SerializePubKey(internalKey),
			RootScriptTreeHash: rootHash,
		},
	}, nil
}

func FromTaprootScriptTree(
	internalKey *btcec.PublicKey,
	tree *taproot.IndexedElementsTapScriptTree,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if internalKey == nil {
		return nil, errors.New("internal key can't be empty or nil")
	}

	if net == nil {
		net = &network.Liquid
	}

	return &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyInternalKey: schnorr.SerializePubKey(internalKey),
			ScriptTree:       tree,
		},
	}, nil
}

func (p *Payment) taprootBech32() (*address.Bech32, error) {
	payload := &address.Bech32{
		Prefix:  p.Network.Bech32,
		Version: segwitVersion,
	}
	if p.Taproot.XOnlyTweakedKey != nil {
		payload.Program = p.Taproot.XOnlyTweakedKey
	} else if p.Taproot.XOnlyInternalKey != nil {
		internalKey, err := schnorr.ParsePubKey(p.Taproot.XOnlyInternalKey)
		if err != nil {
			return nil, err
		}

		if p.Taproot.RootScriptTreeHash != nil {
			payload.Program = schnorr.SerializePubKey(taproot.ComputeTaprootOutputKey(internalKey, p.Taproot.RootScriptTreeHash.CloneBytes()))
		} else {
			if p.Taproot.ScriptTree == nil {
				payload.Program = schnorr.SerializePubKey(taproot.ComputeTaprootKeyNoScript(internalKey))
			} else {
				scriptTreeHash := p.Taproot.ScriptTree.RootNode.TapHash()
				payload.Program = schnorr.SerializePubKey(taproot.ComputeTaprootOutputKey(internalKey, scriptTreeHash.CloneBytes()))
			}
		}
	}

	if payload.Program == nil {
		return nil, errors.New("unable to compute taproot's tweaked key from payment data")
	}

	if len(payload.Program) != 32 {
		return nil, errors.New("taproot's tweaked key has wrong length")
	}

	return payload, nil
}

// WitnessScriptHash is a method of the Payment struct to derive a base58 p2wsh address
func (p *Payment) TaprootAddress() (string, error) {
	payload, err := p.taprootBech32()
	if err != nil {
		return "", err
	}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// ConfidentialWitnessScriptHash is a method of the Payment struct to derive
//a confidential blech32 p2wsh address
func (p *Payment) ConfidentialTaprootAddress() (string, error) {
	bechTaproot, err := p.taprootBech32()
	if err != nil {
		return "", err
	}

	if p.BlindingKey == nil {
		return "", errors.New("blinding key is required to derive confidential address")
	}

	payload := &address.Blech32{
		Prefix:    p.Network.Blech32,
		Version:   bechTaproot.Version,
		Program:   bechTaproot.Program,
		PublicKey: p.BlindingKey.SerializeCompressed(),
	}

	addr, err := address.ToBlech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
}
