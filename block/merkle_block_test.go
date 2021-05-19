package block

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulpemventures/go-elements/elementsutil"
)

func TestDeserializeMerkleBlock(t *testing.T) {
	txOutProof := "00000020e63262b3f7212f346fc8088bc50fc15d578ffa7a969a484cd780ed99423dce2b82fb1822e4fcfab05897c6ecfab6b7e0a70b552951bc511c8e82ec06cc5361436c57a260660000000151000e0000000587eeb38778f35d9a44ae28cf0d92f7c1c878ce03e65df4d9194d7f3d5dabf6bf6b2db058ba5c0ecc190db31a8105eb3c5bd8edd2d26f6e00eb9c89157432cc35afe6dadea994089407fed82cd273afc147985aea90d2ac3fce955439d7419864e3b148c552af357901f8acbd3c50523f3afa90f3d1110f5ffaf95a31084a438ea15030df48db038e38d0b471cce80e11c4353fe70fc917397aca20f1413d7e6a022f00"

	merkleBlock, err := NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	for _, v := range merkleBlock.PartialMerkleTree.TxHashes {
		t.Log(hex.EncodeToString(elementsutil.ReverseBytes(v)))
	}
}

func TestExtractMatches(t *testing.T) {
	txOutProof := "00000020afa83e48050e693352f739f976f24b6c68745306d656400de16ad134dc473600a785d963d5468ccbb6b05095008f01ae94cceb5c951e1047296d9d0279b02256ef7da360660000000151000e00000005972b5316ab084ee55a3bbc8bf2e11b7a8c63e861fe1ff20c6db22ee8ac6f738e4c113d4618449e4f0cb8ff051f0df9dbbc8c5afd6947c82a65275348c102905f8e09f8bba59ef2c018b06841a9664f7a72a963101fd0fae09e4713cc21d903302ae29e6847f143cedaa522488961b32d65a2cebe1e03cfb5f43d309907320776ac45df643be8f2a7edb6c468c3e92b83b7d49f8c9f95abb9050c4f44c7fd3276022f00"

	merkleBlock, err := NewMerkleBlockFromHex(txOutProof)
	if err != nil {
		t.Fatal(err)
	}

	hashMerkleRoot, matchedHashes, err := merkleBlock.ExtractMatches()
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(
		t,
		true,
		bytes.Equal(merkleBlock.BlockHeader.MerkleRoot, hashMerkleRoot.CloneBytes()),
	)
	assert.Equal(t, 1, len(matchedHashes))
}
