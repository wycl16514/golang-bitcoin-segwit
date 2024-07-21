package main

import (
	"encoding/hex"
	"fmt"
	"transaction"
)

func main() {
	txBinary, err := hex.DecodeString("0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000")
	if err != nil {
		panic(err)
	}
	tx := transaction.ParseTransaction(txBinary)
	tx.SetTestnet()
	fmt.Printf("hash:%x\n", tx.Hash())
	//check p2wpkh transaction
	script := tx.GetScript(0, true)
	isP2wpkh := tx.IsP2wpkh(script)
	fmt.Printf("is segwit: %v\n", isP2wpkh)

	//BIP0134 verify message
	z := tx.BIP143SigHash(0)
	fmt.Printf("verify msg: %x\n", z)

	//verify the transaction
	res := tx.Verify()
	fmt.Printf("segwit verify resut: %v\n", res)
}
