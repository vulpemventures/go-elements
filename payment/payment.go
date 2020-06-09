package payment

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil/base58"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"golang.org/x/crypto/ripemd160"
	"hash"
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
func FromPublicKey(
	pubkey *btcec.PublicKey,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) *Payment {
	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}
	publicKeyBytes := pubkey.SerializeCompressed()
	pkHash := hash160(publicKeyBytes)[:ripemd160.Size]
	script := make([]byte, 0)
	script = append([]byte{txscript.OP_0, byte(len(pkHash))}, pkHash...)
	witnessHash := sha256.Sum256(script)
	return &Payment{tmpNet, pubkey, pkHash, blindingKey, nil, script, witnessHash[:]}
}

// FromPublicKeys creates a multi-signature Payment struct from list of public key's
func FromPublicKeys(
	pubkeys []*btcec.PublicKey,
	nrequired int,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if len(pubkeys) < nrequired {
		errorMsg := fmt.Sprintf("unable to generate multisig script with "+
			"%d required signatures when there are only %d public "+
			"keys available", nrequired, len(pubkeys))
		return nil, errors.New(errorMsg)
	}

	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}

	builder := txscript.NewScriptBuilder().AddInt64(int64(nrequired))
	for _, key := range pubkeys {
		builder.AddData(key.SerializeCompressed())
	}
	builder.AddInt64(int64(len(pubkeys)))
	builder.AddOp(txscript.OP_CHECKMULTISIG)

	multiSigScript, err := builder.Script()
	if err != nil {
		return nil, err
	}

	return FromScript(multiSigScript, tmpNet, blindingKey)
}

// FromPayment creates a Payment struct from a another Payment
func FromPayment(payment *Payment) (*Payment, error) {
	if payment.Script == nil || len(payment.Script) == 0 {
		return nil, errors.New("payment's script can't be empty or nil")
	}
	redeem := &Payment{
		payment.Network,
		payment.PublicKey,
		payment.Hash,
		payment.BlindingKey,
		payment.Redeem,
		payment.Script,
		payment.WitnessHash,
	}
	witnessHash := sha256.Sum256(redeem.Script)
	return &Payment{
		payment.Network,
		payment.PublicKey,
		payment.Hash,
		payment.BlindingKey,
		redeem,
		payment.Script,
		witnessHash[:],
	}, nil
}

// FromPayment creates a nested Payment struct from script
func FromScript(
	script []byte,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if script == nil || len(script) == 0 {
		return nil, errors.New("payment's script can't be empty or nil")
	}
	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}

	scriptHash := make([]byte, 0)
	if script[0] == txscript.OP_0 {
		scriptHash = append(scriptHash, script[2:]...)
	}
	if script[0] == txscript.OP_HASH160 {
		scriptHash = append(scriptHash, script[2:len(script)-1]...)
	}
	if script[len(script)-1] == txscript.OP_CHECKMULTISIG {
		scriptHash = hash160(script)
	}

	redeem := &Payment{Network: tmpNet, Hash: scriptHash, Script: script,
		BlindingKey: blindingKey}
	return FromPayment(redeem)
}

// PubKeyHash is a method of the Payment struct to derive a base58 p2pkh address
func (p *Payment) PubKeyHash() string {
	if p.Hash == nil || len(p.Hash) == 0 {
		errors.New("payment's hash can't be empty or nil")
	}
	payload := &address.Base58{p.Network.PubKeyHash, p.Hash}
	addr := address.ToBase58(payload)
	return addr
}

// ConfidentialPubKeyHash is a method of the Payment struct to derive a
//base58 confidential p2pkh address
func (p *Payment) ConfidentialPubKeyHash() string {
	if p.Hash == nil || len(p.Hash) == 0 {
		errors.New("payment's hash can't be empty or nil")
	}
	if p.BlindingKey == nil {
		errors.New("payment's blinding key can't be nil")
	}

	prefix := [1]byte{p.Network.PubKeyHash}
	confidentialAddress := append(
		append(
			prefix[:],
			p.BlindingKey.SerializeCompressed()...,
		),
		p.Hash...,
	)
	return base58.CheckEncode(confidentialAddress, p.Network.Confidential)
}

// ScriptHash is a method of the Payment struct to derive a base58 p2sh address
func (p *Payment) ScriptHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	payload := &address.Base58{p.Network.ScriptHash, p.Hash}
	addr := address.ToBase58(payload)
	return addr, nil
}

// ConfidentialScriptHash is a method of the Payment struct to derive a
//base58 confidential p2sh address
func (p *Payment) ConfidentialScriptHash() string {
	if p.Hash == nil || len(p.Hash) == 0 {
		errors.New("payment's hash can't be empty or nil")
	}
	if p.BlindingKey == nil {
		errors.New("payment's blinding key can't be nil")
	}

	prefix := [1]byte{p.Network.ScriptHash}
	confidentialAddress := append(
		append(
			prefix[:],
			p.BlindingKey.SerializeCompressed()...,
		),
		p.Hash...,
	)
	return base58.CheckEncode(confidentialAddress, p.Network.Confidential)
}

// WitnessPubKeyHash is a method of the Payment struct to derive a base58 p2wpkh address
func (p *Payment) WitnessPubKeyHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Bech32{p.Network.Bech32, version, p.Hash}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
}

// ConfidentialWitnessPubKeyHash is a method of the Payment struct to derive
//a confidential base58 p2wpkh address
func (p *Payment) ConfidentialWitnessPubKeyHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Blech32{
		p.Network.Blech32,
		version,
		p.BlindingKey.SerializeCompressed(),
		p.Hash,
	}
	addr, err := address.ToBlech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
}

// WitnessScriptHash is a method of the Payment struct to derive a base58 p2wsh address
func (p *Payment) WitnessScriptHash() (string, error) {
	if p.Script == nil || len(p.Script) == 0 {
		return "", errors.New("payment's script can't be empty or nil")
	}
	if p.WitnessHash == nil || len(p.WitnessHash) == 0 {
		return "", errors.New("payment's witnessHash can't be empty or nil")
	}

	version := byte(0x00)
	payload := &address.Bech32{p.Network.Bech32, version, p.WitnessHash}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// ConfidentialWitnessScriptHash is a method of the Payment struct to derive
//a confidential base58 p2wsh address
func (p *Payment) ConfidentialWitnessScriptHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Blech32{
		p.Network.Blech32,
		version,
		p.BlindingKey.SerializeCompressed(),
		p.Hash,
	}
	addr, err := address.ToBlech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
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
