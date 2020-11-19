package transaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/fastsha256"
	"github.com/vulpemventures/go-elements/internal/bufferutil"
	"github.com/vulpemventures/go-elements/elementsutil"
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
	if assetAmount < 0 {
		return nil, errors.New("invalid asset amount")
	}
	if tokenAmount < 0 {
		return nil, errors.New("invalid token amount")
	}

	if precision < 0 || precision > 8 {
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

		contractHash = chainhash.HashB(serializedContract)

	}

	confAssetAmount, err := toConfidentialAssetAmount(
		assetAmount,
		precision,
	)
	if err != nil {
		return nil, err
	}
	confTokenAmount, err := toConfidentialTokenAmount(
		tokenAmount,
		precision,
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

// GenerateEntropy generates the entropy from which the hash of the asset and
// of the reissuance token are calculated
func (issuance *TxIssuanceExtended) GenerateEntropy(inTxHash []byte, inTxIndex uint32) error {
	if len(inTxHash) != 32 {
		return errors.New("invalid tx hash length")
	}

	s, err := bufferutil.NewSerializer(nil)
	if err != nil {
		return err
	}

	err = s.WriteSlice(inTxHash)
	if err != nil {
		return err
	}

	err = s.WriteUint32(inTxIndex)
	if err != nil {
		return err
	}

	buf := chainhash.DoubleHashB(s.Bytes())
	buf = append(buf, issuance.ContractHash...)
	entropy := fastsha256.MidState256(buf)

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
	buf = append(issuance.TxIssuance.AssetEntropy, buf...)
	token := fastsha256.MidState256(buf)

	return token[:], nil
}

func toConfidentialAssetAmount(assetAmount uint64, precision uint) ([]byte, error) {
	amount := assetAmount * uint64(math.Pow10(int(precision)))
	confAmount, err := elementsutil.SatoshiToElementsValue(amount)
	if err != nil {
		return nil, err
	}
	return confAmount[:], nil
}

func toConfidentialTokenAmount(tokenAmount uint64, precision uint) ([]byte, error) {
	if tokenAmount == 0 {
		return []byte{0x00}, nil
	}

	amount := tokenAmount * uint64(math.Pow10(int(precision)))
	confAmount, err := elementsutil.SatoshiToElementsValue(amount)
	if err != nil {
		return nil, err
	}
	return confAmount[:], nil
}
