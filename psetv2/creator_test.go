package psetv2_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulpemventures/go-elements/psetv2"
)

var (
	testAddresses = []string{
		"el1qqfttsemg4sapwrfmmccyztj4wa8gpn5yfetkda4z5uy5e2jysgrszmj0xa8tzftde78kvtl26dtxw6q6gcuawte5xeyvkunws",
		"AzpjXSNnwaFpQQwf2A8AUj6Axqa3YXokJtEwmNvQWvoGn2ymKUzmofHmjxBKzPr7bszjrEJRpPSgJqUp",
		"CTExJqr9PvAveGHmK3ymA3YVdBFvEWh1Vqkj5U9DCv4L46BJhhAd3g8SdjPNCZR268VnsaynRGmyzrQa",
	}
)

func TestCreator(t *testing.T) {
	inputs := randomInputArgs(2)
	outputs := randomOutputArgs(6)
	ptx, err := psetv2.New(inputs, outputs, 0)
	require.NoError(t, err)
	require.NotNil(t, ptx)

	psetBase64, err := ptx.ToBase64()
	require.NoError(t, err)
	require.NotEmpty(t, psetBase64)

	parsedPtx, err := psetv2.NewPsetFromBase64(psetBase64)
	require.NoError(t, err)
	require.NotNil(t, parsedPtx)
}

func randomInputArgs(num int) []psetv2.InputArgs {
	ins := make([]psetv2.InputArgs, 0, num)
	for i := 0; i < num; i++ {
		ins = append(ins, psetv2.InputArgs{
			Txid:    randomHex(32),
			TxIndex: randomVout(),
		})
	}
	return ins
}

func randomOutputArgs(num int) []psetv2.OutputArgs {
	outs := make([]psetv2.OutputArgs, 0, num)
	for i := 0; i < num; i++ {
		outs = append(outs, psetv2.OutputArgs{
			Asset:   randomHex(32),
			Amount:  randomValue(),
			Address: testAddresses[i%3],
		})
	}
	return outs
}
