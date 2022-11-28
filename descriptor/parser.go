package descriptor

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strings"
	"unicode"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"

	"github.com/louisinger/btcd/btcec/v2"

	"github.com/btcsuite/btcd/btcutil"
)

const (
	xPrv extendedKeyType = iota
	xPub
)

var (
	ErrInvalidChecksumLength = errors.New("invalid checksum length")
)

func Parse(descriptor string) (Wallet, error) {
	d, err := trimAndValidateChecksum(descriptor)
	if err != nil {
		return nil, err
	}

	return parseScriptExpression(d, true)
}

type extendedKeyType int

func trimAndValidateChecksum(descriptor string) (string, error) {
	str := strings.Split(descriptor, "#")
	switch len(str) {
	case 1:
		return str[0], nil
	case 2:
		if err := validateChecksum(str[1]); err != nil {
			return "", err
		}

		return str[0], nil
	default:
		return "", errors.New("descriptor should contain one # symbol")
	}
}

//TODO impl validate checksum of descriptor
func validateChecksum(checksum string) error {
	if len(checksum) != 8 {
		return ErrInvalidChecksumLength
	}

	return nil
}

func parseScriptExpression(descriptor string, topLevel bool) (Wallet, error) {
	expressionFunc, innerExpression, err := splitFuncAndScriptExpression(descriptor)
	if err != nil {
		return nil, err
	}

	switch expressionFunc {
	case "elsh":

		return nil, nil
	case "elwsh":

		return nil, nil
	case "elpk":

		return nil, nil
	case "elpkh":

		return nil, nil
	case "elwpkh":
		keyInfo, err := parseKeyExpression(innerExpression)
		if err != nil {
			return nil, err
		}

		return newWpkhWalletFromKeyInfo(keyInfo), nil
	case "elcombo":

		return nil, nil
	case "elmulti", "elsortedmulti":

		return nil, nil
	case "elmulti_a":

		return nil, nil
	case "elsortedmulti_a":

		return nil, nil
	case "eltr":

		return nil, nil
	case "eladdr":

		return nil, nil
	case "elraw":

	default:
		return nil, fmt.Errorf("unknown expression: %s", expressionFunc)
	}

	return nil, fmt.Errorf("invalid op '%s'", expressionFunc)
}

func splitFuncAndScriptExpression(s string) (string, string, error) {
	scriptExp, err := regexp.Compile(`(\w+)\((.+)\)`)
	if err != nil {
		return "", "", err
	}

	s = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)

	matches := scriptExp.FindStringSubmatch(s)
	if matches == nil {
		return "", "", errors.New("invalid script")
	}

	if len(matches) != 3 {
		return "", "", errors.New("invalid script")
	}

	return matches[1], matches[2], nil
}

type keyInfo struct {
	keyOrigin       *keyOriginInfo
	pubKey          *string
	wif             *string
	extendedKeyInfo *extendedKeyInfo
}

func parseKeyExpression(keyExpression string) (*keyInfo, error) {
	keyOriginInfo, err := parseKeyOriginInfo(keyExpression)
	if err != nil {
		return nil, err
	}

	keyExpressionTrimmed, err := trimKeyOriginInfo(keyExpression)
	if err != nil {
		return nil, err
	}

	pubKey, wif, extendedKey, err := parseKey(keyExpressionTrimmed)
	if err != nil {
		return nil, err
	}

	return &keyInfo{
		keyOrigin:       keyOriginInfo,
		pubKey:          pubKey,
		wif:             wif,
		extendedKeyInfo: extendedKey,
	}, nil
}

func parseKeyOriginInfo(keyExpression string) (*keyOriginInfo, error) {
	keyExpressionSplit := strings.Split(keyExpression, "]")

	switch len(keyExpressionSplit) {
	case 1:
		return nil, nil
	case 2:
		keyOriginInfo := &keyOriginInfo{}
		if keyExpressionSplit[0][0:1] != "[" {
			return nil, errors.New("key origin start '[ character expected but not found")
		}

		keyOriginSplit := strings.Split(keyExpressionSplit[0], "/")
		fingerprint := keyOriginSplit[0][1:]
		if len(fingerprint) != 8 {
			return nil, errors.New("fingerprint should be 8 char long")
		}

		fingerprintBytes, err := hex.DecodeString(fingerprint)
		if err != nil {
			return nil, fmt.Errorf("fingerprint not valid hex, err: %v", err.Error())
		}

		keyOriginInfo.masterKeyFingerprint = binary.LittleEndian.Uint32(fingerprintBytes)
		if len(keyOriginSplit) > 1 {
			path, err := parsePath(keyOriginSplit[1:])
			if err != nil {
				return nil, err
			}

			keyOriginInfo.path = path
		}

		return keyOriginInfo, nil

	default:
		return nil, errors.New("multiple ']' characters found for a single pubkey")
	}
}

func trimKeyOriginInfo(keyExpression string) (string, error) {
	keyExpressionSplit := strings.Split(keyExpression, "]")

	switch len(keyExpressionSplit) {
	case 1:
		return keyExpressionSplit[0], nil
	case 2:
		return keyExpressionSplit[1], nil
	default:
		return "", errors.New("multiple ']' characters found for a single pubkey")
	}
}

func parsePath(components []string) ([]uint32, error) {
	result := make([]uint32, 0)

	if len(components) == 0 {
		return nil, nil
	}

	for _, component := range components {
		component = strings.TrimSpace(component)
		var value uint32

		if strings.HasSuffix(component, "'") {
			value = hdkeychain.HardenedKeyStart
			component = strings.TrimSpace(
				strings.TrimSuffix(
					component,
					"'",
				),
			)
		} else if strings.HasSuffix(component, "h") {
			value = hdkeychain.HardenedKeyStart
			component = strings.TrimSpace(
				strings.TrimSuffix(
					component,
					"h",
				),
			)
		}
		bigval, ok := new(big.Int).SetString(component, 0)
		if !ok {
			return nil, fmt.Errorf("invalid component: %s", component)
		}
		max := math.MaxUint32 - value
		if bigval.Sign() < 0 || bigval.Cmp(big.NewInt(int64(max))) > 0 {
			if value == 0 {
				return nil, fmt.Errorf("component %v out of allowed "+
					"range [0, %d]", bigval, max)
			}
			return nil, fmt.Errorf("component %v out of allowed "+
				"hardened range [0, %d]", bigval, max)
		}
		value += uint32(bigval.Uint64())

		result = append(result, value)
	}
	return result, nil
}

type keyOriginInfo struct {
	masterKeyFingerprint uint32
	path                 []uint32
}

type extendedKeyInfo struct {
	key     string
	path    []uint32
	keyType extendedKeyType
	isRange bool
}

func parseKey(keyExpression string) (*string, *string, *extendedKeyInfo, error) {
	var (
		key     string
		pathStr string
	)

	keyExpSplit := strings.Split(keyExpression, "/")
	if len(keyExpSplit) == 1 {
		key = keyExpSplit[0]
	} else {
		key = keyExpSplit[0]
		pathStr = keyExpression[len(keyExpSplit[0]):]
	}

	if isPubKey(key) {
		return &key, nil, nil, nil
	}

	if isWif(key) {
		return nil, &key, nil, nil
	}

	if isExtended(key) {
		extendedKeyInfo := &extendedKeyInfo{}

		extendedKeyInfo.key = key

		extendedKeyInfo.keyType = xPub
		if strings.HasPrefix(key, "xprv") {
			extendedKeyInfo.keyType = xPrv
		}

		if pathStr != "" {
			pathStr = pathStr[1:] // remove prefix '/'
			if strings.HasSuffix(pathStr, "/*") {
				extendedKeyInfo.isRange = true
				pathStr = pathStr[:len(pathStr)-2] // remove suffix '/*'
			}
			path, err := parsePath(strings.Split(pathStr, "/"))
			if err != nil {
				return nil, nil, nil, err
			}

			extendedKeyInfo.path = path
		}

		return nil, nil, extendedKeyInfo, nil
	}

	return nil, nil, nil, errors.New("unrecognised key")
}

func isPubKey(pubKey string) bool {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return false
	}

	_, err = btcec.ParsePubKey(pubKeyBytes)
	return err == nil
}

func isWif(wif string) bool {
	_, err := btcutil.DecodeWIF(wif)

	return err == nil
}

func isExtended(extendedKey string) bool {
	return strings.HasPrefix(extendedKey, "xprv") || strings.HasPrefix(extendedKey, "xpub")
}
