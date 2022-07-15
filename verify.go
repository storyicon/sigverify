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

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
)

// VerifySignatureEx is used to verify text signature
func VerifySignatureEx(ctx context.Context, client *ethclient.Client, address ethcommon.Address, msg []byte, signature []byte) (bool, error) {
	if ok, err := VerifyEllipticCurveSignatureEx(address, msg, signature); err == nil && ok {
		return true, nil
	}
	return VerifyERC1271Signature(ctx, client, address, msg, signature)
}

// VerifyHexSignatureEx is used to verify text signature
func VerifyHexSignatureEx(ctx context.Context, client *ethclient.Client, address ethcommon.Address, msg []byte, signature string) (bool, error) {
	sigBytes, err := HexDecode(signature)
	if err != nil {
		return false, err
	}
	return VerifySignatureEx(ctx, client, address, msg, sigBytes)
}
