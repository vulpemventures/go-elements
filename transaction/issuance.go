package transaction

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/fastsha256"
	"github.com/vulpemventures/go-elements/elementsutil"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
)

// IssuanceEntity defines one of the fields of the issuance contract
type IssuanceEntity struct {
	Domain string `json:"domain"`
}

// IssuanceContract defines the structure of the Ricardian contract of the issuance
type IssuanceContract struct {
	Name      string         `json:"name"`
	Ticker    string         `json:"ticker"`
	Version   uint           `json:"version"`
	Precision uint           `json:"precision"`
	PubKey    string         `json:"issuer_pubkey"`
	Entity    IssuanceEntity `json:"entity"`
}

// TxIssuance defines the type for Issuance field in TxInput
type TxIssuance struct {
	AssetBlindingNonce []byte
	AssetEntropy       []byte
	AssetAmount        []byte
	TokenAmount        []byte
}

// IsReissuance returns whether the issuance is an asset re-issuance
func (issuance *TxIssuance) IsReissuance() bool {
	return !bytes.Equal(issuance.AssetBlindingNonce, Zero[:])
}

// HasTokenAmount returns whether the token amount is defined for the issuance
func (issuance *TxIssuance) HasTokenAmount() bool {
	return len(issuance.TokenAmount) > 1
}

// TxIssuanceExtended adds fields to the issuance type that are not encoded in
// the transaction
type TxIssuanceExtended struct {
	TxIssuance
	Precision    uint
	ContractHash []byte
}

// NewTxIssuanceFromInput returns the extended issuance for the given input
func NewTxIssuanceFromInput(in *TxInput) (*TxIssuanceExtended, error) {
	if in.Issuance.IsReissuance() {
		return NewTxIssuanceFromEntropy(in.Issuance.AssetEntropy), nil
	}

	iss := NewTxIssuanceFromContractHash(in.Issuance.AssetEntropy)
	if err := iss.GenerateEntropy(in.Hash, in.Index); err != nil {
		return nil, err
	}
	return iss, nil
}

// NewTxIssuanceFromContractHash returns a new issuance instance from contract hash
func NewTxIssuanceFromContractHash(contractHash []byte) *TxIssuanceExtended {
	return &TxIssuanceExtended{ContractHash: contractHash}
}

// NewTxIssuanceFromEntropy returns a new issuance instance from entropy
func NewTxIssuanceFromEntropy(entropy []byte) *TxIssuanceExtended {
	issuance := &TxIssuanceExtended{
		TxIssuance: TxIssuance{AssetEntropy: entropy},
	}
	return issuance
}

// NewTxIssuance returns a new issuance instance
func NewTxIssuance(
	assetAmount uint64,
	tokenAmount uint64,
	precision uint,
	contract *IssuanceContract,
) (*TxIssuanceExtended, error) {
	if precision > 8 {
		return nil, errors.New("invalid precision")
	}

	// Use the default `0x00..00` 32-byte array if contract is not set
	contractHash := make([]byte, 32)
	if contract != nil {
		if contract.Precision != precision {
			return nil, errors.New(
				"precision declared in contract does not match the one" +
					"set as argument",
			)
		}

		serializedContract, err := json.Marshal(contract)
		if err != nil {
			return nil, err
		}

		tmp, err := orderJsonKeysLexographically(serializedContract)
		if err != nil {
			return nil, err
		}

		contractHash = chainhash.HashB(tmp)
	}

	confAssetAmount, err := toConfidentialIssuanceAmount(
		assetAmount,
	)
	if err != nil {
		return nil, err
	}

	confTokenAmount, err := toConfidentialIssuanceAmount(
		tokenAmount,
	)
	if err != nil {
		return nil, err
	}

	issuance := TxIssuance{
		AssetAmount:        confAssetAmount,
		TokenAmount:        confTokenAmount,
		AssetBlindingNonce: make([]byte, 32),
	}

	return &TxIssuanceExtended{
		TxIssuance:   issuance,
		Precision:    precision,
		ContractHash: contractHash,
	}, nil
}

func ComputeEntropy(inTxHash []byte, inTxIndex uint32, contractHash []byte) ([]byte, error) {
	if len(inTxHash) != 32 {
		return nil, errors.New("invalid tx hash length")
	}

	s := bufferutil.NewSerializer(nil)

	err := s.WriteSlice(inTxHash)
	if err != nil {
		return nil, err
	}

	err = s.WriteUint32(inTxIndex)
	if err != nil {
		return nil, err
	}

	buf := chainhash.DoubleHashB(s.Bytes())
	buf = append(buf, contractHash...)
	entropy := fastsha256.MidState256(buf)

	return entropy[:], nil
}

// GenerateEntropy generates the entropy from which the hash of the asset and
// of the reissuance token are calculated
func (issuance *TxIssuanceExtended) GenerateEntropy(inTxHash []byte, inTxIndex uint32) error {
	entropy, err := ComputeEntropy(inTxHash, inTxIndex, issuance.ContractHash)
	if err != nil {
		return err
	}

	issuance.TxIssuance.AssetEntropy = entropy[:]
	return nil
}

// GenerateAsset calculates the asset hash for the given issuance
func (issuance *TxIssuanceExtended) GenerateAsset() ([]byte, error) {
	if issuance.TxIssuance.AssetEntropy == nil || len(issuance.TxIssuance.AssetEntropy) <= 0 {
		return nil, errors.New("issuance entropy must not be nil")
	}

	buf := append(issuance.TxIssuance.AssetEntropy, make([]byte, 32)...)
	asset := fastsha256.MidState256(buf)

	return asset[:], nil
}

// GenerateReissuanceToken calculates the asset hash for the given issuance
func (issuance *TxIssuanceExtended) GenerateReissuanceToken(flag uint) ([]byte, error) {
	if issuance.TxIssuance.AssetEntropy == nil || len(issuance.TxIssuance.AssetEntropy) <= 0 {
		return nil, errors.New("issuance entropy must not be nil")
	}
	if flag != 0 && flag != 1 {
		return nil, errors.New("invalid flag for reissuance token")
	}

	buf := make([]byte, 32)
	buf[0] = byte(flag + 1)
	// write zero to empty
	for i := 1; i < 32; i++ {
		buf[i] = 0
	}
	buf = append(issuance.TxIssuance.AssetEntropy, buf...)
	token := fastsha256.MidState256(buf)

	return token[:], nil
}

func toConfidentialIssuanceAmount(tokenAmount uint64) ([]byte, error) {
	if tokenAmount == 0 {
		return []byte{0x00}, nil
	}

	confAmount, err := elementsutil.ValueToBytes(tokenAmount)
	if err != nil {
		return nil, err
	}
	return confAmount[:], nil
}

func orderJsonKeysLexographically(bytes []byte) ([]byte, error) {
	var ifce interface{}
	err := json.Unmarshal(bytes, &ifce)
	if err != nil {
		return []byte{}, err
	}
	output, err := json.Marshal(ifce)
	if err != nil {
		return []byte{}, err
	}
	return output, nil
}
