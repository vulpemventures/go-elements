package psetv2

import (
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeserializationAndSerialization(t *testing.T) {
	file, err := ioutil.ReadFile("testdata/deserialize.json")
	if err != nil {
		t.Fatal(err)
	}
	var tests []map[string]interface{}
	err = json.Unmarshal(file, &tests)

	for _, v := range tests {
		testName := v["name"].(string)
		t.Run(testName, func(t *testing.T) {
			ptx, err := NewPsetFromBase64(v["base64"].(string))
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
				return
			}

			b, err := ptx.ToBase64()
			if err != nil {
				t.Errorf("test: %v, err: %v", testName, err)
				return
			}

			assert.Equal(t, v["base64"].(string), b)
		})
	}
}

func TestPsetValidateInputTimeLock(t *testing.T) {
	type fields struct {
		Global  *Global
		Inputs  []Input
		Outputs []Output
	}
	type args struct {
		input Input
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "first input",
			fields: fields{
				Global: &Global{
					txInfo: TxInfo{
						fallBackLockTime: uint32Ptr(2),
					},
				},
			},
			args: args{
				input: Input{
					requiredHeightLocktime: uint32Ptr(1),
				},
			},
			wantErr: false,
		},
		{
			name: "provided height with existing time-lock",
			fields: fields{
				Inputs: []Input{
					{
						requiredTimeLocktime: uint32Ptr(10),
					},
					{
						requiredTimeLocktime: uint32Ptr(11),
					},
				},
			},
			args: args{
				input: Input{
					requiredHeightLocktime: uint32Ptr(1),
				},
			},
			wantErr: true,
		},
		{
			name: "provided time with existing height-lock",
			fields: fields{
				Inputs: []Input{
					{
						requiredHeightLocktime: uint32Ptr(10),
					},
				},
			},
			args: args{
				input: Input{
					requiredTimeLocktime: uint32Ptr(1),
				},
			},
			wantErr: true,
		},
		{
			name: "provided time-lock greater then existing",
			fields: fields{
				Global: &Global{
					txInfo: TxInfo{
						fallBackLockTime: uint32Ptr(2),
					},
				},
				Inputs: []Input{
					{
						requiredTimeLocktime: uint32Ptr(10),
					},
				},
			},
			args: args{
				input: Input{
					requiredTimeLocktime: uint32Ptr(11),
				},
			},
			wantErr: false,
		},
		{
			name: "provided height-lock greater then existing",
			fields: fields{
				Global: &Global{
					txInfo: TxInfo{
						fallBackLockTime: uint32Ptr(2),
					},
				},
				Inputs: []Input{
					{
						requiredHeightLocktime: uint32Ptr(10),
					},
				},
			},
			args: args{
				input: Input{
					requiredHeightLocktime: uint32Ptr(11),
				},
			},
			wantErr: false,
		},
		{
			name: "has partial signature",
			fields: fields{
				Global: &Global{
					txInfo: TxInfo{
						fallBackLockTime: uint32Ptr(2),
					},
				},
				Inputs: []Input{
					{
						partialSigs: []PartialSig{
							{
								PubKey:    []byte{11},
								Signature: []byte{11},
							},
						},
						requiredHeightLocktime: uint32Ptr(10),
					},
				},
			},
			args: args{
				input: Input{
					requiredHeightLocktime: uint32Ptr(11),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Pset{
				Global:  tt.fields.Global,
				Inputs:  tt.fields.Inputs,
				Outputs: tt.fields.Outputs,
			}
			if err := p.validateInputTimeLock(tt.args.input); (err != nil) != tt.wantErr {
				t.Errorf("validateInputTimeLock() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func uint32Ptr(x uint32) *uint32 {
	return &x
}
