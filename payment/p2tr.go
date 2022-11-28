package payment

import (
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/louisinger/btcd/btcec/v2"
	"github.com/louisinger/btcd/btcec/v2/schnorr"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"github.com/vulpemventures/go-elements/taproot"
)

const (
	taprootSegwitVersion = byte(0x01)
)

var (
	ErrTaprootDataIsNil = errors.New("taproot payment data is required to derive taproot addresses")
	ErrNetworkIsNil     = errors.New("network is required to derive taproot addresses")
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

	p2tr := &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyTweakedKey: schnorr.SerializePubKey(tweakedKey),
		},
	}

	if err := p2tr.setP2TRScript(); err != nil {
		return nil, err
	}

	return p2tr, nil
}

// FromTaprootScriptTreeHash creates a taproot payment from a merkle script tree hash and internal key
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

	p2tr := &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyInternalKey:   schnorr.SerializePubKey(internalKey),
			RootScriptTreeHash: rootHash,
		},
	}

	if err := p2tr.setP2TRScript(); err != nil {
		return nil, err
	}

	return p2tr, nil
}

// FromTaprootScriptTree creates a taproot payment from a merkle script tree and internal key
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

	p2tr := &Payment{
		Network:     net,
		BlindingKey: blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyInternalKey: schnorr.SerializePubKey(internalKey),
			ScriptTree:       tree,
		},
	}

	if err := p2tr.setP2TRScript(); err != nil {
		return nil, err
	}

	return p2tr, nil
}

func (p2tr *Payment) setP2TRScript() error {
	addr, err := p2tr.TaprootAddress()
	if err != nil {
		return err
	}

	script, err := address.ToOutputScript(addr)
	if err != nil {
		return err
	}

	p2tr.Script = script
	return nil
}

func (p *Payment) taprootBech32() (*address.Bech32, error) {
	if p.Taproot == nil {
		return nil, ErrTaprootDataIsNil
	}

	if p.Network == nil {
		return nil, ErrNetworkIsNil
	}

	payload := &address.Bech32{
		Prefix:  p.Network.Bech32,
		Version: taprootSegwitVersion,
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

// TaprootAddress derives the unconditional Taproot address from the payment data
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

// ConfidentialTaprootAddress derives a confidential segwit v1 address from the payment taproot data
func (p *Payment) ConfidentialTaprootAddress() (string, error) {
	if p.BlindingKey == nil {
		return "", errors.New("blinding key is required to derive confidential address")
	}

	bechTaproot, err := p.taprootBech32()
	if err != nil {
		return "", err
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
