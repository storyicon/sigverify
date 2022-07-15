// Copyright 2022 storyicon@foxmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sigverify

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEcRecover(t *testing.T) {
	type args struct {
		data []byte
		sig  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "standard",
			args: args{
				data: []byte(`hello`),
				sig:  MustMustHexDecode(t, "0x0498c6564863c78e663848b963fde1ea1d860d5d882d2abdb707d1e9179ff80630a4a71705da534a562c08cb64a546c6132de26eb77a44f086832cbc1dbe01f71b"),
			},
			want:    "0xb052C02346F80cF6ae4DF52c10FABD3e0aD24d81",
			wantErr: assert.NoError,
		},
		{
			name: "ledger",
			args: args{
				data: []byte(`abc`),
				sig:  MustMustHexDecode(t, "0xb6a1ef0b63715a4d303e3935e4a6c75c89ead4311c089e98082e7eaf7e4b460a19e998df7c9ad308e4e5db376364b9e5e4b6f75c4628452cedd13641d1099c8e00"),
			},
			want: "",
			wantErr: func(t assert.TestingT, err error, msgAndArgs ...interface{}) bool {
				if err != nil && err.Error() == "invalid Ethereum signature (V is not 27 or 28)" {
					return false
				}
				assert.Fail(t, fmt.Sprintf("Received unexpected error:\n%+v", err), msgAndArgs...)
				return true
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EcRecover(tt.args.data, tt.args.sig)
			if !tt.wantErr(t, err, fmt.Sprintf("EcRecover(%v, %v)", tt.args.data, tt.args.sig)) {
				return
			}
			assert.Equalf(t, tt.want, got.Hex(), "EcRecover(%v, %v)", tt.args.data, tt.args.sig)
		})
	}
}

func TestEcRecoverEx(t *testing.T) {
	type args struct {
		data []byte
		sig  []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "standard",
			args: args{
				data: []byte(`hello`),
				sig:  MustMustHexDecode(t, "0x0498c6564863c78e663848b963fde1ea1d860d5d882d2abdb707d1e9179ff80630a4a71705da534a562c08cb64a546c6132de26eb77a44f086832cbc1dbe01f71b"),
			},
			want:    "0xb052C02346F80cF6ae4DF52c10FABD3e0aD24d81",
			wantErr: assert.NoError,
		},
		{
			name: "ledger",
			args: args{
				data: []byte(`abc`),
				sig:  MustMustHexDecode(t, "0xb6a1ef0b63715a4d303e3935e4a6c75c89ead4311c089e98082e7eaf7e4b460a19e998df7c9ad308e4e5db376364b9e5e4b6f75c4628452cedd13641d1099c8e00"),
			},
			want:    "0x545087bd36c7F0eFaeC26252Ee62085CA9A726AC",
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EcRecoverEx(tt.args.data, tt.args.sig)
			if !tt.wantErr(t, err, fmt.Sprintf("EcRecoverEx(%v, %v)", tt.args.data, tt.args.sig)) {
				return
			}
			assert.Equalf(t, tt.want, got.Hex(), "EcRecoverEx(%v, %v)", tt.args.data, tt.args.sig)
		})
	}
}
