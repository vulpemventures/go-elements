package payment

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/txscript"
	"github.com/louisinger/btcd/btcec/v2"
	"github.com/vulpemventures/go-elements/address"
	"github.com/vulpemventures/go-elements/network"
	"golang.org/x/crypto/ripemd160"
)

// Payment defines the structure that holds the information different addresses
type Payment struct {
	Hash          []byte
	WitnessHash   []byte
	Script        []byte
	WitnessScript []byte
	Redeem        *Payment
	PublicKey     *btcec.PublicKey
	BlindingKey   *btcec.PublicKey
	Network       *network.Network
	Taproot       *TaprootPaymentData
}

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
	pkHash := Hash160(publicKeyBytes)
	script := buildScript(pkHash, "p2pkh")
	witnessScript := buildScript(pkHash, "p2wpkh")

	return &Payment{
		Hash:          pkHash,
		WitnessHash:   pkHash,
		Script:        script,
		WitnessScript: witnessScript,
		Network:       tmpNet,
		PublicKey:     pubkey,
		BlindingKey:   blindingKey,
	}
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

	redeem, err := FromScript(multiSigScript, tmpNet, blindingKey)
	if err != nil {
		return nil, err
	}

	return FromPayment(redeem)
}

// FromPayment creates a Payment struct from a another Payment
func FromPayment(payment *Payment) (*Payment, error) {
	if payment.Script == nil || len(payment.Script) == 0 {
		return nil, errors.New("payment's script can't be empty or nil")
	}

	redeem := payment.copy()
	scriptToHash := make([]byte, 0)
	// the only case where the witnessScript is null is when wrapping multisig
	if len(redeem.WitnessScript) > 0 {
		scriptToHash = redeem.WitnessScript
	} else {
		scriptToHash = redeem.Script
	}
	scriptHash := Hash160(scriptToHash)
	witnessScriptHash := sha256.Sum256(scriptToHash)
	script := buildScript(scriptHash, "p2sh")
	witnessScript := buildScript(witnessScriptHash[:], "p2wsh")

	return &Payment{
		Hash:          scriptHash,
		WitnessHash:   witnessScriptHash[:],
		Script:        script,
		WitnessScript: witnessScript,
		Redeem:        redeem,
		Network:       redeem.Network,
		BlindingKey:   redeem.BlindingKey,
		Taproot:       redeem.Taproot,
	}, nil
}

// FromScript creates parses a script into a Payment struct
func FromScript(
	outputScript []byte,
	net *network.Network,
	blindingKey *btcec.PublicKey,
) (*Payment, error) {
	if len(outputScript) == 0 {
		return nil, errors.New("payment's script can't be empty or nil")
	}

	var tmpNet *network.Network
	if net == nil {
		tmpNet = &network.Liquid
	} else {
		tmpNet = net
	}

	var script, scriptHash, witnessScript, witnessScriptHash, tweakedKey []byte
	switch address.GetScriptType(outputScript) {
	case address.P2WpkhScript:
		scriptHash = outputScript[2:]
		script = buildScript(scriptHash, "p2pkh")
		witnessScriptHash = scriptHash
		witnessScript = outputScript
	case address.P2WshScript:
		witnessScriptHash = outputScript[2:]
		witnessScript = outputScript
	case address.P2ShScript:
		scriptHash = outputScript[2 : len(outputScript)-1]
		script = outputScript
	case address.P2PkhScript:
		scriptHash = outputScript[3 : len(outputScript)-2]
		script = outputScript
	case address.P2TRScript:
		tweakedKey = outputScript[2:]
		script = outputScript
	// multisig, here we do not calculate the hashes because this payment
	// must be wrapped into another one
	default:
		script = outputScript
	}

	return &Payment{
		Hash:          scriptHash,
		WitnessHash:   witnessScriptHash,
		Script:        script,
		WitnessScript: witnessScript,
		Network:       tmpNet,
		BlindingKey:   blindingKey,
		Taproot: &TaprootPaymentData{
			XOnlyTweakedKey: tweakedKey,
		},
	}, nil
}

// PubKeyHash is a method of the Payment struct to derive a base58 p2pkh address
func (p *Payment) PubKeyHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	payload := &address.Base58{p.Network.PubKeyHash, p.Hash}
	addr := address.ToBase58(payload)
	return addr, nil
}

// ConfidentialPubKeyHash is a method of the Payment struct to derive a
//base58 confidential p2pkh address
func (p *Payment) ConfidentialPubKeyHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	if p.BlindingKey == nil {
		return "", errors.New("payment's blinding key can't be nil")
	}

	prefix := [1]byte{p.Network.PubKeyHash}
	confidentialAddress := append(
		append(
			prefix[:],
			p.BlindingKey.SerializeCompressed()...,
		),
		p.Hash...,
	)
	return base58.CheckEncode(confidentialAddress, p.Network.Confidential), nil
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
func (p *Payment) ConfidentialScriptHash() (string, error) {
	if p.Hash == nil || len(p.Hash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	if p.BlindingKey == nil {
		return "", errors.New("payment's blinding key can't be nil")
	}

	prefix := [1]byte{p.Network.ScriptHash}
	confidentialAddress := append(
		append(
			prefix[:],
			p.BlindingKey.SerializeCompressed()...,
		),
		p.Hash...,
	)
	return base58.CheckEncode(confidentialAddress, p.Network.Confidential), nil
}

// WitnessPubKeyHash is a method of the Payment struct to derive a base58 p2wpkh address
func (p *Payment) WitnessPubKeyHash() (string, error) {
	if p.WitnessHash == nil || len(p.WitnessHash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Bech32{p.Network.Bech32, version, p.WitnessHash}
	addr, err := address.ToBech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
}

// ConfidentialWitnessPubKeyHash is a method of the Payment struct to derive
//a confidential blech32 p2wpkh address
func (p *Payment) ConfidentialWitnessPubKeyHash() (string, error) {
	if p.WitnessHash == nil || len(p.WitnessHash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Blech32{
		p.Network.Blech32,
		version,
		p.BlindingKey.SerializeCompressed(),
		p.WitnessHash,
	}
	addr, err := address.ToBlech32(payload)
	if err != nil {
		return "", err
	}
	return addr, nil
}

// WitnessScriptHash is a method of the Payment struct to derive a base58 p2wsh address
func (p *Payment) WitnessScriptHash() (string, error) {
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
//a confidential blech32 p2wsh address
func (p *Payment) ConfidentialWitnessScriptHash() (string, error) {
	if p.WitnessHash == nil || len(p.WitnessHash) == 0 {
		return "", errors.New("payment's hash can't be empty or nil")
	}
	//Here the Version for wpkh is always 0
	version := byte(0x00)
	payload := &address.Blech32{
		p.Network.Blech32,
		version,
		p.BlindingKey.SerializeCompressed(),
		p.WitnessHash,
	}
	addr, err := address.ToBlech32(payload)
	if err != nil {
		return "", nil
	}
	return addr, nil
}

func (p *Payment) copy() *Payment {
	var redeem *Payment
	var pubkey *btcec.PublicKey
	var blindkey *btcec.PublicKey
	if p.Redeem != nil {
		redeem = &Payment{}
		*redeem = *p.Redeem
	}
	if p.PublicKey != nil {
		pubkey = &btcec.PublicKey{}
		*pubkey = *p.PublicKey
	}
	if p.BlindingKey != nil {
		blindkey = &btcec.PublicKey{}
		*blindkey = *p.BlindingKey
	}
	return &Payment{
		Hash:          p.Hash,
		WitnessHash:   p.WitnessHash,
		Script:        p.Script,
		WitnessScript: p.WitnessScript,
		Redeem:        redeem,
		PublicKey:     pubkey,
		BlindingKey:   blindkey,
		Network:       p.Network,
	}
}

// Calculate the hash of hasher over buf.
func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// Hash160 calculates the hash ripemd160(sha256(b)).
func Hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

// buildScript returns the requested scriptType script with the provided hash
func buildScript(hash []byte, scriptType string) []byte {
	builder := txscript.NewScriptBuilder()

	switch scriptType {
	case "p2pkh":
		builder.AddOp(txscript.OP_DUP).AddOp(txscript.OP_HASH160)
		builder.AddData(hash)
		builder.AddOp(txscript.OP_EQUALVERIFY).AddOp(txscript.OP_CHECKSIG)
	case "p2sh":
		builder.AddOp(txscript.OP_HASH160).AddData(hash).AddOp(txscript.OP_EQUAL)
	case "p2wpkh", "p2wsh":
		builder.AddOp(txscript.OP_0).AddData(hash)
	}

	script, _ := builder.Script()
	return script
}
