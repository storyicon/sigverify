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

func MustMustHexDecode(t *testing.T, data string) []byte {
	raw, err := HexDecode(data)
	assert.Equal(t, nil, err, "failed to decode hex")
	return raw
}

func TestVerifyERC1271HexSignature(t *testing.T) {
	client, err := ethclient.Dial("https://polygon-rpc.com")
	assert.Equal(t, nil, err, "failed to connect to mainnet")
	type args struct {
		ctx       context.Context
		client    *ethclient.Client
		address   common.Address
		data      []byte
		signature string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   common.HexToAddress("0x4836A472ab1dd406ECb8D0F933A985541ee3921f"),
				data:      MustMustHexDecode(t, "0x787177"),
				signature: "0xc0f8db6019888d87a0afc1299e81ef45d3abce64f63072c8d7a6ef00f5f82c1522958ff110afa98b8c0d23b558376db1d2fbab4944e708f8bf6dc7b977ee07201b00",
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   common.HexToAddress("0x05c57d74256fdb3212da51e70647bf7ab36e8889"),
				data:      MustMustHexDecode(t, "0x787177"),
				signature: "0xc0f8db6019888d87a0afc1299e81ef45d3abce64f63072c8d7a6ef00f5f82c1522958ff110afa98b8c0d23b558376db1d2fbab4944e708f8bf6dc7b977ee07201b00",
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return IsErrExecutionReverted(err)
			},
		},
		{
			args: args{
				ctx:       context.Background(),
				client:    client,
				address:   common.HexToAddress("0xf4a62fc079f47e9df86ed298f792b3aed13891ed"),
				data:      MustMustHexDecode(t, "0x787177"),
				signature: "0xc0f8db6019888d87a0afc1299e81ef45d3abce64f63072c8d7a6ef00f5f82c1522958ff110afa98b8c0d23b558376db1d2fbab4944e708f8bf6dc7b977ee07201b00",
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return IsErrNoContractCode(err)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyERC1271HexSignature(tt.args.ctx, tt.args.client, tt.args.address, tt.args.data, tt.args.signature)
			if !tt.wantErr(t, err, fmt.Sprintf("VerifyERC1271HexSignature(%v, %v, %v, %v, %v)", tt.args.ctx, tt.args.client, tt.args.address, tt.args.data, tt.args.signature)) {
				return
			}
			assert.Equalf(t, tt.want, got, "VerifyERC1271HexSignature(%v, %v, %v, %v, %v)", tt.args.ctx, tt.args.client, tt.args.address, tt.args.data, tt.args.signature)
		})
	}
}
