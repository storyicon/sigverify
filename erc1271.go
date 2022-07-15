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

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/storyicon/sigverify/contracts/erc1271"
)

// magicValueERC1271 is defined in the ERC1271 standard, which comes from:
// bytes4(keccak256("isValidSignature(bytes32,bytes)")
var magicValueERC1271 = [4]byte{
	22, 38, 186, 126,
}

// GetERC1271Magic is used to get the magic value defined by ERC1271
func GetERC1271Magic() [4]byte {
	return magicValueERC1271
}

// VerifyERC1271HexSignature is a helper function.
// look up VerifyERC1271 for more comments.
func VerifyERC1271HexSignature(ctx context.Context, client *ethclient.Client, address ethcommon.Address, data []byte, signature string) (bool, error) {
	sig, err := HexDecode(signature)
	if err != nil {
		return false, err
	}
	return VerifyERC1271Signature(ctx, client, address, data, sig)
}

// VerifyERC1271Signature verifies signatures based on the ERC1271 standard
// 1. When the given address is EOA, "no contract code at given address" will be thrown:
// 2. When the given address is a contract but does not conform to the erc1271 specification, "execution reverted" will be thrown
func VerifyERC1271Signature(ctx context.Context, client *ethclient.Client, address ethcommon.Address, data []byte, signature []byte) (bool, error) {
	contract, err := erc1271.NewErc1271(address, client)
	if err != nil {
		return false, err
	}
	dataHash := ethcommon.BytesToHash(accounts.TextHash(data))
	magic, err := contract.IsValidSignature(&bind.CallOpts{
		Context: ctx,
	}, dataHash, signature)
	if err != nil {
		return false, err
	}
	return GetERC1271Magic() == magic, nil
}
