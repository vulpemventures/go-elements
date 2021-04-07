package block

import (
	"bytes"
	"errors"

	"github.com/vulpemventures/go-elements/internal/bufferutil"

	"github.com/vulpemventures/go-elements/transaction"
)

func deserialize(buf *bytes.Buffer) (*Block, error) {
	header, err := DeserializeHeader(buf)
	if err != nil {
		return nil, err
	}

	transactions, err := DeserializeTransactions(buf)
	if err != nil {
		return nil, err
	}

	return &Block{
		Header: header,
		TransactionsData: &Transactions{
			Transactions: transactions,
		},
	}, nil
}

func DeserializeHeader(
	buf *bytes.Buffer,
) (*Header, error) {
	d := bufferutil.NewDeserializer(buf)

	version, err := d.ReadUint32()
	if err != nil {
		return nil, err
	}

	isDyna := version>>31 == 1
	if isDyna {
		version = blockVersion
	}

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
		Version:       version,
		PrevBlockHash: prevBlockHash,
		MerkleRoot:    merkleRoot,
		Timestamp:     timestamp,
		Height:        blockHeight,
		ExtData:       extData,
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
		Proof:             proof,
		DynamicFederation: dynamicFederation,
		IsDyna:            isDyna,
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
		Current:          currentParams,
		Proposed:         proposedParams,
		SignBlockWitness: signBlockWitness,
	}, nil
}

func deserializeDynamicFederationParams(
	d *bufferutil.Deserializer,
) (*DynamicFederationParams, error) {
	var compactParams *CompactParams
	var fullParams *FullParams
	var err error

	serializeType, err := d.ReadUint8()
	if err != nil {
		return nil, err
	}

	switch serializeType {
	case null:
		return nil, nil
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

	return &DynamicFederationParams{
		CompactParams: compactParams,
		FullParams:    fullParams,
	}, nil
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
		SignBlockScript:       signBlockScript,
		SignBlockWitnessLimit: signBlockWitnessLimit,
		ElidedRoot:            elidedRoot,
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
		SignBlockScript:       signBlockScript,
		SignBlockWitnessLimit: signBlockWitnessLimit,
		FedpegProgram:         fedpegProgram,
		FedpegScript:          fedpegScript,
		ExtensionSpace:        extensionSpace,
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
		Challenge: challenge,
		Solution:  solution,
	}, nil
}

func DeserializeTransactions(
	buf *bytes.Buffer,
) ([]*transaction.Transaction, error) {
	d := bufferutil.NewDeserializer(buf)

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
