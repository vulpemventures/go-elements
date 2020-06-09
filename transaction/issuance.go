package transaction

import (
	"encoding/json"
	"errors"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/vulpemventures/fastsha256"
	"github.com/vulpemventures/go-elements/confidential"
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
	Entity    IssuanceEntity `json:"entity"`
}

// TxIssuance defines the type for Issuance field in TxInput
type TxIssuance struct {
	AssetBlindingNonce []byte
	AssetEntropy       []byte
	AssetAmount        []byte
	TokenAmount        []byte
}

// TxIssuanceExtended adds fields to the issuance type that are not encoded in
// the transaction
type TxIssuanceExtended struct {
	TxIssuance
	Precision uint
}

// NewTxIssuance returns a new empty issuance instance
func NewTxIssuance(assetAmount, tokenAmount float64, precision uint) (*TxIssuanceExtended, error) {
	if assetAmount < 0 {
		return nil, errors.New("invalid asset amount")
	}
	if tokenAmount < 0 {
		return nil, errors.New("invalid token amount")
	}
	if precision < 0 || precision > 8 {
		return nil, errors.New("invalid precision")
	}

	aa := uint64(assetAmount * math.Pow10(int(8-precision)))
	ta := uint64(tokenAmount * math.Pow10(int(8-precision)))
	confAssetAmount, err := confidential.SatoshiToElementsValue(aa)
	if err != nil {
		return nil, err
	}
	confTokenAmount, err := confidential.SatoshiToElementsValue(ta)
	if err != nil {
		return nil, err
	}

	issuance := TxIssuance{
		AssetAmount: confAssetAmount[:],
		TokenAmount: confTokenAmount[:],
	}

	return &TxIssuanceExtended{
		TxIssuance: issuance,
		Precision:  precision,
	}, nil
}

// GenerateEntropy generates the entropy from which the hash of the asset and
// of the reissuance token are calculated
func (issuance *TxIssuanceExtended) GenerateEntropy(inTxHash []byte, inTxIndex uint32, contract *IssuanceContract) error {
	if len(inTxHash) != 32 {
		return errors.New("invalid tx hash length")
	}

	// Use the default `0x00..00` 32-byte array if contract is not set
	contractHash := make([]byte, 32)
	if contract != nil {
		if contract.Precision != issuance.Precision {
			return errors.New(
				"precision declared in contract does not match the one" +
					"set for the issuance",
			)
		}
		serializedContract, err := json.Marshal(contract)
		if err != nil {
			return err
		}
		contractHash = chainhash.HashB(serializedContract)
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
	buf = append(buf, contractHash...)
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
