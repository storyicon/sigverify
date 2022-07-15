# SigVerify

This project is used to verify signatures under various specifications of ethereum. In addition to the standard elliptic curve signature, it also supports the signature of wallets such as ledger and argent.

It supports:
1. Standard elliptic curve signature verification. (eth_sign).
2. EIP712 typed data verification. (eth_signTypedData_v*).
3. ERC1271 Smart contract wallet signature verification (isValidSignature).
4. Some hardware wallets signature verification such as ledger.