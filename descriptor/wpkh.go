package descriptor

import (
	"encoding/hex"
	"errors"

	"github.com/btcsuite/btcutil/hdkeychain"

	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcutil"
)

const (
	// numOfScripts to be generated in case wpkh wallet is "range"
	numOfScripts = 100
)

type WpkhWallet struct {
	keyInfo *keyInfo
}

func newWpkhWalletFromKeyInfo(info *keyInfo) WpkhWallet {
	return WpkhWallet{
		keyInfo: info,
	}
}

func (w WpkhWallet) Type() string {
	return "wpkh"
}

func (w WpkhWallet) IsRange() bool {
	if w.keyInfo.extendedKeyInfo != nil {
		return w.keyInfo.extendedKeyInfo.isRange
	}

	return false
}

func (w WpkhWallet) Script(opts *ScriptOpts) ([]ScriptResponse, error) {
	response := make([]ScriptResponse, 0)

	var (
		numOfScriptsToBeGenerated        = 1
		index                     uint32 = 0
		generateMoreScripts              = false
	)

	if w.IsRange() {
		numOfScriptsToBeGenerated = numOfScripts
		if opts != nil {
			if opts.numOfScripts != nil {
				generateMoreScripts = true
				numOfScriptsToBeGenerated = *opts.numOfScripts
			} else {
				index = *opts.index
			}
		}
	}

	if w.keyInfo.pubKey != nil {
		pubKeyBytes, err := hex.DecodeString(*w.keyInfo.pubKey)
		if err != nil {
			return nil, err
		}

		script, err := wpkhScriptFromBytes(pubKeyBytes)
		if err != nil {
			return nil, err
		}

		response = append(response, ScriptResponse{
			Script: script,
		})

		return response, nil
	}

	if w.keyInfo.wif != nil {
		wif, err := btcutil.DecodeWIF(*w.keyInfo.wif)
		if err != nil {
			return nil, err
		}

		script, err := wpkhScriptFromBytes(wif.PrivKey.PubKey().SerializeCompressed())
		if err != nil {
			return nil, err
		}

		response = append(response, ScriptResponse{
			Script: script,
		})

		return response, nil
	}

	if w.keyInfo.extendedKeyInfo != nil {
		masterExtKey, err := hdkeychain.NewKeyFromString(w.keyInfo.extendedKeyInfo.key)
		if err != nil {
			return nil, err
		}

		for _, v := range w.keyInfo.extendedKeyInfo.path {
			masterExtKey, err = masterExtKey.Child(v)
			if err != nil {
				return nil, err
			}
		}

		if w.keyInfo.extendedKeyInfo.isRange {
			if generateMoreScripts {
				for i := 0; i < numOfScriptsToBeGenerated; i++ {
					childKey, err := masterExtKey.Child(uint32(i))
					if err != nil {
						return nil, err
					}
					pubKey, err := childKey.ECPubKey()
					if err != nil {
						return nil, err
					}

					script, err := wpkhScriptFromBytes(pubKey.SerializeCompressed())
					if err != nil {
						return nil, err
					}

					response = append(response, ScriptResponse{
						DerivationPath: w.derivationPath(uint32(i)),
						Script:         script,
					})
				}
			} else {
				childKey, err := masterExtKey.Child(index)
				if err != nil {
					return nil, err
				}
				pubKey, err := childKey.ECPubKey()
				if err != nil {
					return nil, err
				}

				script, err := wpkhScriptFromBytes(pubKey.SerializeCompressed())
				if err != nil {
					return nil, err
				}

				response = append(response, ScriptResponse{
					DerivationPath: w.derivationPath(index),
					Script:         script,
				})
			}
		}

		return response, nil
	}

	return nil, errors.New("parser didnt recognised puKey, wif not extended keys in expression")
}

func (w WpkhWallet) derivationPath(index uint32) []uint32 {
	derivationPath := make([]uint32, 0)
	derivationPath = append(derivationPath, w.keyInfo.keyOrigin.masterKeyFingerprint)
	derivationPath = append(derivationPath, w.keyInfo.keyOrigin.path...)
	derivationPath = append(derivationPath, w.keyInfo.extendedKeyInfo.path...)
	derivationPath = append(derivationPath, index)

	return derivationPath
}

func wpkhScriptFromBytes(pubKeyBytes []byte) ([]byte, error) {
	pkHash := hash160(pubKeyBytes)
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_0).AddData(pkHash)

	script, err := builder.Script()
	if err != nil {
		return nil, err
	}

	return script, nil
}
