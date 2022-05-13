package descriptor

import (
	"encoding/hex"
	"errors"
	"reflect"
	"testing"
)

func TestTrimAndValidateChecksum(t *testing.T) {
	type args struct {
		descriptor string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				descriptor: "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
			},
			want:    "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
			wantErr: false,
		},
		{
			name: "2",
			args: args{
				descriptor: "sh(L4rK1yDtC#WekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "3",
			args: args{
				descriptor: "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)#12345678",
			},
			want:    "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
			wantErr: false,
		},
		{
			name: "4",
			args: args{
				descriptor: "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)#1234568",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "5",
			args: args{
				descriptor: "sh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuP#LBcCU2z8TrisoyY1)#12345678",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := trimAndValidateChecksum(tt.args.descriptor)
			if (err != nil) != tt.wantErr {
				t.Errorf("trimAndValidateChecksum() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("trimAndValidateChecksum() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParsePath(t *testing.T) {
	type args struct {
		components []string
	}
	tests := []struct {
		name    string
		args    args
		want    []uint32
		wantErr bool
	}{
		{
			name: "1",
			args: args{
				components: []string{"13'"},
			},
			want:    []uint32{2147483661},
			wantErr: false,
		},
		{
			name: "2",
			args: args{
				components: []string{"13h"},
			},
			want:    []uint32{2147483661},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePath(tt.args.components)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parsePath() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseScriptExpressionWpkh(t *testing.T) {
	type args struct {
		descriptor string
		topLevel   bool
	}
	tests := []struct {
		name     string
		args     args
		validate func(wallet Wallet) error
		wantErr  bool
	}{
		{
			name: "wpkh_pub_key",
			args: args{
				descriptor: "wpkh(03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "00149a1c78a507689f6f54b847ad1cef1e614ee23f1e"
				scripts, err := wallet.Script(nil)
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_wif",
			args: args{
				descriptor: "wpkh(L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "00149a1c78a507689f6f54b847ad1cef1e614ee23f1e"
				scripts, err := wallet.Script(nil)
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpriv_with_index_1",
			args: args{
				descriptor: "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "0014326b2249e3a25d5dc60935f044ee835d090ba859"
				scripts, err := wallet.Script(WithIndex(0))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpriv_with_index_1",
			args: args{
				descriptor: "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
				scripts, err := wallet.Script(WithIndex(1))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpriv_with_range",
			args: args{
				descriptor: "wpkh([ffffffff/13']xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected1 := "0014326b2249e3a25d5dc60935f044ee835d090ba859"
				scriptHexExpected2 := "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
				scriptHexExpected3 := "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"

				scripts, err := wallet.Script(WithRange(3))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected1 {
					return errors.New("unexpected script gen")
				}

				scripts[0].DerivationPath[0] = 4294967295
				scripts[0].DerivationPath[1] = 2147483661
				scripts[0].DerivationPath[2] = 1
				scripts[0].DerivationPath[3] = 2
				scripts[0].DerivationPath[4] = 0

				if hex.EncodeToString(scripts[1].Script) != scriptHexExpected2 {
					return errors.New("unexpected script gen")
				}

				scripts[1].DerivationPath[0] = 4294967295
				scripts[1].DerivationPath[1] = 2147483661
				scripts[1].DerivationPath[2] = 1
				scripts[1].DerivationPath[3] = 2
				scripts[1].DerivationPath[4] = 1

				if hex.EncodeToString(scripts[2].Script) != scriptHexExpected3 {
					return errors.New("unexpected script gen")
				}

				scripts[2].DerivationPath[0] = 4294967295
				scripts[2].DerivationPath[1] = 2147483661
				scripts[2].DerivationPath[2] = 1
				scripts[2].DerivationPath[3] = 2
				scripts[2].DerivationPath[4] = 2

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpub_with_range",
			args: args{
				descriptor: "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected1 := "0014326b2249e3a25d5dc60935f044ee835d090ba859"
				scriptHexExpected2 := "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
				scriptHexExpected3 := "00141fa798efd1cbf95cebf912c031b8a4a6e9fb9f27"

				scripts, err := wallet.Script(WithRange(3))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected1 {
					return errors.New("unexpected script gen")
				}

				scripts[0].DerivationPath[0] = 4294967295
				scripts[0].DerivationPath[1] = 2147483661
				scripts[0].DerivationPath[2] = 1
				scripts[0].DerivationPath[3] = 2
				scripts[0].DerivationPath[4] = 0

				if hex.EncodeToString(scripts[1].Script) != scriptHexExpected2 {
					return errors.New("unexpected script gen")
				}

				scripts[1].DerivationPath[0] = 4294967295
				scripts[1].DerivationPath[1] = 2147483661
				scripts[1].DerivationPath[2] = 1
				scripts[1].DerivationPath[3] = 2
				scripts[1].DerivationPath[4] = 1

				if hex.EncodeToString(scripts[2].Script) != scriptHexExpected3 {
					return errors.New("unexpected script gen")
				}

				scripts[2].DerivationPath[0] = 4294967295
				scripts[2].DerivationPath[1] = 2147483661
				scripts[2].DerivationPath[2] = 1
				scripts[2].DerivationPath[3] = 2
				scripts[2].DerivationPath[4] = 2

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpub_with_index_1",
			args: args{
				descriptor: "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "0014326b2249e3a25d5dc60935f044ee835d090ba859"
				scripts, err := wallet.Script(WithIndex(0))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
		{
			name: "wpkh_xpub_with_index_1",
			args: args{
				descriptor: "wpkh([ffffffff/13']xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/1/2/*)",
				topLevel:   true,
			},
			validate: func(wallet Wallet) error {
				scriptHexExpected := "0014af0bd98abc2f2cae66e36896a39ffe2d32984fb7"
				scripts, err := wallet.Script(WithIndex(1))
				if err != nil {
					return err
				}

				if hex.EncodeToString(scripts[0].Script) != scriptHexExpected {
					return errors.New("unexpected script gen")
				}

				return nil
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseScriptExpression(tt.args.descriptor, tt.args.topLevel)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseScriptExpression() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err := tt.validate(got); err != nil {
				t.Error(err)
				return
			}
		})
	}
}
