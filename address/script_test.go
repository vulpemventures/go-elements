package address

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMultiSigExtract(t *testing.T) {
	// 1 of 1 multisig
	fedpegScript := "512103dff4923d778550cc13ce0d887d737553b4b58f4e8e886507fc39f5e447b2186451ae"
	bytes, err := hex.DecodeString(fedpegScript)
	if err != nil {
		t.Fatal(err)
	}

	scriptDetails, err := ExtractScriptDetails(bytes)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, MultiSigTy, scriptDetails.Class)
	assert.Equal(t, 1, len(scriptDetails.Data))
	assert.Equal(t, 33, len(scriptDetails.Data[0]))
	assert.Equal(t, 1, scriptDetails.NumOfPublicKeys)
	assert.Equal(t, 1, scriptDetails.RequiredSignatures)
	assert.Equal(t, 4, len(scriptDetails.Pops))
}

func TestMultisigExtractFedScriptV1(t *testing.T) {
	fedpegScriptV1 := "745c87635b21020e0338c96a8870479f2396c373cc7696ba124e8635d41b0ea581112b678172612102675333a4e4b8fb51d9d4e22fa5a8eaced3fdac8a8cbf9be8c030f75712e6af992102896807d54bc55c24981f24a453c60ad3e8993d693732288068a23df3d9f50d4821029e51a5ef5db3137051de8323b001749932f2ff0d34c82e96a2c2461de96ae56c2102a4e1a9638d46923272c266631d94d36bdb03a64ee0e14c7518e49d2f29bc40102102f8a00b269f8c5e59c67d36db3cdc11b11b21f64b4bffb2815e9100d9aa8daf072103079e252e85abffd3c401a69b087e590a9b86f33f574f08129ccbd3521ecf516b2103111cf405b627e22135b3b3733a4a34aa5723fb0f58379a16d32861bf576b0ec2210318f331b3e5d38156da6633b31929c5b220349859cc9ca3d33fb4e68aa08401742103230dae6b4ac93480aeab26d000841298e3b8f6157028e47b0897c1e025165de121035abff4281ff00660f99ab27bb53e6b33689c2cd8dcd364bc3c90ca5aea0d71a62103bd45cddfacf2083b14310ae4a84e25de61e451637346325222747b157446614c2103cc297026b06c71cbfa52089149157b5ff23de027ac5ab781800a578192d175462103d3bde5d63bdb3a6379b461be64dad45eabff42f758543a9645afd42f6d4248282103ed1e8d5109c9ed66f7941bc53cc71137baa76d50d274bda8d5e8ffbd6e61fe9a5f6702c00fb275522103aab896d53a8e7d6433137bbba940f9c521e085dd07e60994579b64a6d992cf79210291b7d0b1b692f8f524516ed950872e5da10fb1b808b5a526dedc6fed1cf29807210386aa9372fbab374593466bc5451dc59954e90787f08060964d95c87ef34ca5bb5368ae"
	bytes, err := hex.DecodeString(fedpegScriptV1)
	if err != nil {
		t.Fatal(err)
	}

	scriptDetails, err := ExtractScriptDetails(bytes)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println(binary.LittleEndian.Uint16(scriptDetails.Pops[22].Data))
	assert.Equal(t, MultiSigTy, scriptDetails.Class)
}
