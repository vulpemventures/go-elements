package block

import (
	"bytes"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/vulpemventures/go-elements/transaction"
)

func deserialize(buf *bytes.Buffer) (*Block, error) {
	d := bufferutil.NewDeserializer(buf)

	header, err := deserializeHeader(d)
	if err != nil {
		return nil, err
	}

	transactions, err := deserializeTransactions(d, buf)
	if err != nil {
		return nil, err
	}

	return &Block{
		Header:       header,
		Transactions: transactions,
	}, nil
}

func deserializeHeader(
	d *bufferutil.Deserializer,
) (*Header, error) {
	version, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	isDyna := false
	if version>>31 == 1 {
		isDyna = true
	}
	version = blockVersion

	prevBlockHash, err := d.ReadSlice(hashSize)
	if err != nil {
		return nil, err
	}

	merkleRoot, err := d.ReadSlice(hashSize)
	if err != nil {
		return nil, err
	}

	timestamp, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	blockHeight, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	extData, err := deserializeExtData(d, isDyna)
	if err != nil {
		return nil, err
	}

	return &Header{
		version:       version,
		prevBlockHash: prevBlockHash,
		merkleRoot:    merkleRoot,
		time:          timestamp,
		height:        blockHeight,
		ext:           extData,
	}, nil
}

func deserializeExtData(
	d *bufferutil.Deserializer,
	isDyna bool,
) (*ExtData, error) {
	var dynamicFederation *DynamicFederation
	var proof *Proof
	var err error
	if isDyna {
		dynamicFederation, err = deserializeDynamicFederation(d)
		if err != nil {
			return nil, err
		}
	} else {
		proof, err = deserializeProof(d)
		if err != nil {
			return nil, err
		}
	}

	return &ExtData{
		proof:             proof,
		dynamicFederation: dynamicFederation,
	}, nil
}

func deserializeDynamicFederation(
	d *bufferutil.Deserializer,
) (*DynamicFederation, error) {
	currentParams, err := deserializeDynamicFederationParams(d)
	if err != nil {
		return nil, err
	}

	proposedParams, err := deserializeDynamicFederationParams(d)
	if err != nil {
		return nil, err
	}

	signBlockWitness, err := deserializeSignBlockWitness(d)
	if err != nil {
		return nil, err
	}

	return &DynamicFederation{
		current:          currentParams,
		proposed:         proposedParams,
		signBlockWitness: signBlockWitness,
	}, nil
}

func deserializeDynamicFederationParams(
	d *bufferutil.Deserializer,
) (*DynamicFederationParams, error) {
	var dynamicFederationParams *DynamicFederationParams
	var compactParams *CompactParams
	var fullParams *FullParams
	var err error
	nul := false

	serializeType, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	switch serializeType {
	case null:
		nul = true
	case compact:
		compactParams, err = deserializeCompactParams(d)
		if err != nil {
			return nil, err
		}
	case full:
		fullParams, err = deserializeFullParams(d)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("bad serialize type for dynafed parameters")
	}

	if !nul {
		dynamicFederationParams = &DynamicFederationParams{
			compactParams: compactParams,
			fullParams:    fullParams,
		}
	}

	return dynamicFederationParams, nil
}

func deserializeCompactParams(
	d *bufferutil.Deserializer,
) (*CompactParams, error) {
	signBlockScriptLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	signBlockScript, err := d.ReadSlice(uint(signBlockScriptLength))
	if err != nil {
		return nil, err
	}

	signBlockWitnessLimit, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	elidedRoot, err := d.ReadSlice(hashSize)
	if err != nil {
		return nil, err
	}

	return &CompactParams{
		signBlockScript:       signBlockScript,
		signBlockWitnessLimit: signBlockWitnessLimit,
		elidedRoot:            elidedRoot,
	}, nil
}

func deserializeFullParams(
	d *bufferutil.Deserializer,
) (*FullParams, error) {
	signBlockScriptLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	signBlockScript, err := d.ReadSlice(uint(signBlockScriptLength))
	if err != nil {
		return nil, err
	}

	signBlockWitnessLimit, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	fedpegProgramLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	fedpegProgram, err := d.ReadSlice(uint(fedpegProgramLength))
	if err != nil {
		return nil, err
	}

	fedpegScriptLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	fedpegScript, err := d.ReadSlice(uint(fedpegScriptLength))
	if err != nil {
		return nil, err
	}

	extensionSpaceLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	extensionSpace := make([][]byte, 0, extensionSpaceLength)
	for i := 0; i < int(extensionSpaceLength); i++ {
		tmpLen, err := d.ReadVarInt()
		if err != nil {
			return nil, err
		}
		tmp, err := d.ReadSlice(uint(tmpLen))
		if err != nil {
			return nil, err
		}
		extensionSpace = append(extensionSpace, tmp)
	}

	return &FullParams{
		signBlockScript:       signBlockScript,
		signBlockWitnessLimit: signBlockWitnessLimit,
		fedpegProgram:         fedpegProgram,
		fedpegScript:          fedpegScript,
		extensionSpace:        extensionSpace,
	}, nil
}

func deserializeSignBlockWitness(
	d *bufferutil.Deserializer,
) ([][]byte, error) {
	signBlockWitnessLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}
	signBlockWitness := make([][]byte, 0, signBlockWitnessLength)
	for i := 0; i < int(signBlockWitnessLength); i++ {
		tmpLen, err := d.ReadVarInt()
		if err != nil {
			return nil, err
		}
		tmp, err := d.ReadSlice(uint(tmpLen))
		if err != nil {
			return nil, err
		}
		signBlockWitness = append(signBlockWitness, tmp)
	}

	return signBlockWitness, nil
}

func deserializeProof(
	d *bufferutil.Deserializer,
) (*Proof, error) {
	challengeLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	challenge, err := d.ReadSlice(uint(challengeLength))
	if err != nil {
		return nil, err
	}

	solutionLength, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	solution, err := d.ReadSlice(uint(solutionLength))
	if err != nil {
		return nil, err
	}

	return &Proof{
		challenge: challenge,
		solution:  solution,
	}, nil
}

func deserializeTransactions(
	d *bufferutil.Deserializer,
	buf *bytes.Buffer,
) ([]*transaction.Transaction, error) {
	txCount, err := d.ReadVarInt()
	if err != nil {
		return nil, err
	}

	txs := make([]*transaction.Transaction, 0)
	for i := 0; i < int(txCount); i++ {
		tx, err := transaction.NewTxFromBuffer(buf)
		if err != nil {
			return nil, err
		}
		txs = append(txs, tx)
	}

	return txs, nil
}
