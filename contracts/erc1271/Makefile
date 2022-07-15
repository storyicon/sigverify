default:compile
compile:
	solc-0.8.7 --optimize-runs=10000 --optimize --overwrite --abi ERC1271.sol --bin -o .
	abigen --bin=ERC1271.bin --abi=ERC1271.abi --pkg=erc1271 --out=erc1271.go
