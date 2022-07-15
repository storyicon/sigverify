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
	"context"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/assert"
)

func TestVerifyHexSignatureEx(t *testing.T) {
	client, err := ethclient.Dial("https://polygon-rpc.com")
	assert.Equal(t, nil, err)
	type args struct {
		ctx       context.Context
		client    *ethclient.Client
		address   string
		msg       []byte
		signature string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "curve",
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   "0xb052C02346F80cF6ae4DF52c10FABD3e0aD24d81",
				msg:       []byte("hello"),
				signature: "0x0498c6564863c78e663848b963fde1ea1d860d5d882d2abdb707d1e9179ff80630a4a71705da534a562c08cb64a546c6132de26eb77a44f086832cbc1dbe01f71b",
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "ledger",
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   "0x545087bd36c7F0eFaeC26252Ee62085CA9A726AC",
				msg:       []byte("abc"),
				signature: "0xb6a1ef0b63715a4d303e3935e4a6c75c89ead4311c089e98082e7eaf7e4b460a19e998df7c9ad308e4e5db376364b9e5e4b6f75c4628452cedd13641d1099c8e00",
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "erc1271/without 0x prefix",
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   "0x4836A472ab1dd406ECb8D0F933A985541ee3921f",
				msg:       MustMustHexDecode(t, "787177"),
				signature: "c0f8db6019888d87a0afc1299e81ef45d3abce64f63072c8d7a6ef00f5f82c1522958ff110afa98b8c0d23b558376db1d2fbab4944e708f8bf6dc7b977ee07201b00",
			},
			want:    true,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyHexSignatureEx(tt.args.ctx, tt.args.client, common.HexToAddress(tt.args.address), tt.args.msg, tt.args.signature)
			if !tt.wantErr(t, err, fmt.Sprintf("VerifyHexSignatureEx(%v, %v, %v, %v, %v)", tt.args.ctx, tt.args.client, tt.args.address, tt.args.msg, tt.args.signature)) {
				return
			}
			assert.Equalf(t, tt.want, got, "VerifyHexSignatureEx(%v, %v, %v, %v, %v)", tt.args.ctx, tt.args.client, tt.args.address, tt.args.msg, tt.args.signature)
		})
	}
}
