package elementsutil_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/elementsutil"
)

func TestValueFromToBytes(t *testing.T) {
	value := uint64(1000000000)
	rawValue, err := elementsutil.ValueToBytes(value)
	require.NoError(t, err)

	val, err := elementsutil.ValueFromBytes(rawValue)
	require.NoError(t, err)

	require.Equal(t, value, val)
}

func TestAssetFromToBytes(t *testing.T) {
	asset := "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
	rawAsset, err := elementsutil.AssetHashToBytes(asset)
	require.NoError(t, err)

	ass := elementsutil.AssetHashFromBytes(rawAsset)
	require.Equal(t, asset, ass)
}

func TestTxIDFromToBytes(t *testing.T) {
	txid := "c222325b5fd879163ac9014b410e6f27a1411572e807c28c12748ad94022de72"
	rawTxid, err := elementsutil.TxIDToBytes(txid)
	require.NoError(t, err)

	txhash := elementsutil.TxIDFromBytes(rawTxid)
	require.Equal(t, txid, txhash)
}
