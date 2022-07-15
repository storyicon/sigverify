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

	"github.com/ethereum/go-ethereum/accounts"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// VerifyEllipticCurveSignatureEx is used to verify elliptic curve signatures
// It calls the EcRecoverEx function to verify the signature.
func VerifyEllipticCurveSignatureEx(address ethcommon.Address, data []byte, signature []byte) (bool, error) {
	recovered, err := EcRecoverEx(data, signature)
	if err != nil {
		return false, err
	}
	return recovered == address, nil
}

// VerifyEllipticCurveHexSignatureEx is used to verify elliptic curve signatures
// It calls the EcRecoverEx function to verify the signature.
func VerifyEllipticCurveHexSignatureEx(address ethcommon.Address, data []byte, signature string) (bool, error) {
	sig, err := HexDecode(signature)
	if err != nil {
		return false, err
	}
	return VerifyEllipticCurveSignatureEx(address, data, sig)
}

// VerifyEllipticCurveSignature is used to verify the elliptic curve signature
// It calls the native ecrecover function to verify the signature
func VerifyEllipticCurveSignature(address ethcommon.Address, data []byte, signature []byte) (bool, error) {
	recovered, err := EcRecover(data, signature)
	if err != nil {
		return false, err
	}
	return recovered == address, nil
}

// EcRecoverEx is an extension to EcRecover that supports more signature formats, such as ledger signatures.
func EcRecoverEx(data []byte, sig []byte) (ethcommon.Address, error) {
	return RecoveryAddressEx(accounts.TextHash(data), sig)
}

// RecoveryAddressEx is an extension to RecoveryAddress that supports more signature formats, such as ledger signatures.
func RecoveryAddressEx(data []byte, sig []byte) (ethcommon.Address, error) {
	sig = CopyBytes(sig)
	if len(sig) != crypto.SignatureLength {
		return ethcommon.Address{}, fmt.Errorf("signature must be %d bytes long", crypto.SignatureLength)
	}
	// comment(storyicon): fix ledger wallet
	// https://ethereum.stackexchange.com/questions/103307/cannot-verifiy-a-signature-produced-by-ledger-in-solidity-using-ecrecover
	if sig[crypto.RecoveryIDOffset] == 0 || sig[crypto.RecoveryIDOffset] == 1 {
		sig[crypto.RecoveryIDOffset] += 27
	}
	return RecoveryAddress(data, sig)
}

// RecoveryAddress returns the address for the account that was used to create the signature, this function is almost a fork of EcRecover
// However, EcRecover in go-ethereum will automatically perform accounts.TextHash for data in EcRecover,
// which makes EIP712 unable to reuse this function
// This design makes the function lose versatility, so this behavior is changed here
func RecoveryAddress(data []byte, sig []byte) (ethcommon.Address, error) {
	sig = CopyBytes(sig)
	if len(sig) != crypto.SignatureLength {
		return ethcommon.Address{}, fmt.Errorf("signature must be %d bytes long", crypto.SignatureLength)
	}
	if sig[crypto.RecoveryIDOffset] != 27 && sig[crypto.RecoveryIDOffset] != 28 {
		return ethcommon.Address{}, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[crypto.RecoveryIDOffset] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(data, sig)
	if err != nil {
		return ethcommon.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

// EcRecover returns the address for the account that was used to create the signature,
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19Ethereum Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be 27 or 28 for legacy reasons.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_ecRecover
func EcRecover(data []byte, sig []byte) (ethcommon.Address, error) {
	return RecoveryAddress(accounts.TextHash(data), sig)
}
