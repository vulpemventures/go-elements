package payment

import (
	"crypto/sha256"
	"errors"
	"github.com/btcsuite/btcd/btcec"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"golang.org/x/crypto/ripemd160"
	"hash"
)

const (
	Op0 = 0x00
)

// Payment defines the structure that holds the information different addresses
type Payment struct {
	Network     *network.Network
	PublicKey   *btcec.PublicKey
	Hash        []byte
	BlindingKey *btcec.PublicKey
	Redeem      *Payment
	Script      []byte
	WitnessHash []byte
}

//target mail duty exit light void budget zone senior tag rude wisdom
// priv 1cc080a4cd371eafcad489a29664af6a7276b362fe783443ce036552482b971d
// pub 036f5646ed688b9279369da0a4ad78953ae7e6d300436ca8a3264360efe38236e3

// FromPublicKey creates a Payment struct from a btcec.publicKey
func FromPublicKey(pubkey *btcec.PublicKey, net *network.Network) *Payment {
	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}
	publicKeyBytes := pubkey.SerializeCompressed()
	pkHash := hash160(publicKeyBytes)[:ripemd160.Size]
	script := make([]byte, 0)
	script = append([]byte{Op0, byte(len(pkHash))}, pkHash...)
	witnessHash := sha256.Sum256(script)
	return &Payment{tmpNet, pubkey, pkHash, nil, nil, script, witnessHash[:]}
}

// FromPayment creates a Payment struct from a another Payment
func FromPayment(payment *Payment) (*Payment, error) {
	if payment.Script == nil {
		return nil, errors.New("script can't be nil")
	}
	redeem := &Payment{payment.Network, payment.PublicKey, payment.Hash, payment.BlindingKey, payment.Redeem, payment.Script, payment.WitnessHash}
	return &Payment{payment.Network, nil, hash160(redeem.Script), nil, redeem, nil, nil}, nil
}

// FromPayment creates a nested Payment struct from script
func FromScript(script []byte, net *network.Network) (*Payment, error) {
	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}
	redeem := &Payment{Network: tmpNet, Script: script}
	return FromPayment(redeem)
}

// PubKeyHash is a method of the Payment struct to derive a base58 p2pkh address
func (p *Payment) PubKeyHash() string {
	payload := &address.Base58{p.Network.PubKeyHash, p.Hash}
	addr := address.ToBase58(payload)
	return addr
}

// ScriptHash is a method of the Payment struct to derive a base58 p2sh address
func (p *Payment) ScriptHash() string {
	payload := &address.Base58{p.Network.ScriptHash, p.Hash}
	addr := address.ToBase58(payload)
	return addr
}

// WitnessPubKeyHash is a method of the Payment struct to derive a base58 p2wpkh address
func (p *Payment) WitnessPubKeyHash() string {
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Bech32{p.Network.Bech32, version, p.Hash}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return ""
	}
	return addr
}

// WitnessScriptHash is a method of the Payment struct to derive a base58 p2wsh address
func (p *Payment) WitnessScriptHash() string {
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Bech32{p.Network.Bech32, version, p.WitnessHash}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return ""
	}
	return addr
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}
