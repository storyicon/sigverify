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
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/stretchr/testify/assert"
)

func TestVerifyTypedDataHexSignatureEx(t *testing.T) {
	chainId := math.HexOrDecimal256(*big.NewInt(1))
	type args struct {
		address   common.Address
		data      apitypes.TypedData
		signature string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "TypedData",
			args: args{
				address: common.HexToAddress("0xaC39b311DCEb2A4b2f5d8461c1cdaF756F4F7Ae9"),
				data: apitypes.TypedData{
					Types: apitypes.Types{
						"EIP712Domain": []apitypes.Type{
							{Name: "name", Type: "string"},
							{Name: "chainId", Type: "uint256"},
						},
						"RandomAmbireTypeStruct": []apitypes.Type{
							{Name: "identity", Type: "address"},
							{Name: "rewards", Type: "uint256"},
						},
					},
					Domain: apitypes.TypedDataDomain{
						Name:    "Ambire Typed test message",
						ChainId: &chainId,
					},
					PrimaryType: "RandomAmbireTypeStruct",
					Message: apitypes.TypedDataMessage{
						"identity": "0x0000000000000000000000000000000000000000",
						"rewards":  "0",
					},
				},
				signature: "0xee0d9f9e63fa7183bea2ca2e614cf539464a4c120c8dfc1d5ccc367f242a2c5939d7f59ec2ab413b8a9047de5de2f1e5e97da4eba2ef0d6a89136464f992dae11c",
			},
			want:    true,
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := VerifyTypedDataHexSignatureEx(tt.args.address, tt.args.data, tt.args.signature)
			if !tt.wantErr(t, err, fmt.Sprintf("VerifyTypedDataHexSignatureEx(%v, %v, %v)", tt.args.address, tt.args.data, tt.args.signature)) {
				return
			}
			assert.Equalf(t, tt.want, got, "VerifyTypedDataHexSignatureEx(%v, %v, %v)", tt.args.address, tt.args.data, tt.args.signature)
		})
	}
}
