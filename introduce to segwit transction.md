In previous section of talking about transaction, we have seen some transactions have a bit of segwit set to 1. Which indicates such transactions is a kind of "segreagated witness" transaction, it is an
upgrade of the tranditional transaction and now it is almost the mainstream transaction. In this section we will go into the details of segwit transaction.

There are many benefits brough by segwit transaction compare with the old stye transaction:

1, Block size increase

2, Transaction malleability fix

3, segwit versioning for clear upgrade paths

4, quadratic hashing fix

5, offline wallet fee calculation security

The list aboved is not easy to understand, we may understand them after we going to the details of segwit transaction that is pay-to-witness-pubkey-hash transaction (p2wpkh). We have senn the 
pay-to-pubkey-hash transaction(p2pkh) before, and p2wpkh is an upgrade for p2pkh. In p2pkh, we combine instructions with data together, but in p2wpkh transaction, we seperate data in ScriptSig to
its own witness field.

There is a jargon word "transaction malleability", it is the ability to change the transaction id without changing the transaction's intention. The malleability of transaction ID will bright many
security breaks for creation of payment channel, as we know transaction id is the hash result for content of the transaction, if any data changed in the transaction and the hash will be invalid.
But there is possible that the ScirptSig field changed for the transaction input may keep the transaction hash remain the same, because this field will be cleared beofore computing the transaction
hash.

Therefore changing the ScriptSig field for transaction input will not affect the transaction hash result. If the transactoin data can be changed without affecting its hash result, then the uniqueness
of a transaction will not be guaranteed by the hash id. In order to mitigate the problem bring by empting ScriptSig field when computing the hash, p2wpkh transaction will seperate data from scriptsig
field and put it into another field.

Let's have a look on segwit transaction:

010000000115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac00000000

1, the first four bytes in little endian format is version: 01000000

2, the following field is varint it is the count of input: 0x01

3, the following 32 bytes in little endian is previous transaction hash:
15e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f856

4, the following four bytes in little endian is previous transaction index: 01000000

5, the following one byte 0x00 is scriptsig

6, the following four bytes in little endian is sequence number : ffffffff

7, the following is varint fot the count of output: 0x01

8, the following 8 bytes in little endian is output amount: 0b4f50500000000

9, the following data chunk is ScriptPubKey: 1976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac

10, the last four byte in little endian is locktime: 00000000

Let's check the same transaction with segwit upgrade:

0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000

1, the first 4 bytes in little endian is version: 01000000

2, the following one byte is segwit marker: 00

3, the following one byte is segwit flag: 01

4, the following field is variant for input count: 01

5, the follwing 32 bytes in little endian is previous transaction hash:
15e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f856

6, the follwoing 4 bytes in little endian is previous transaction index: 01000000

7, the following one byte is scriptsig: 00

8, the following 4 bytes in little endian format is sequence: ffffffff

9, the following varint is number of output: 01

10, the following 8 bytes in little endian is output amount: 00b4f50500000000

11, the following chunk is scriptpubkey: 1976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac

12, the following data chunk is witness: 
02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac

do the following for each input:
----> 1, the first field is variant, it is number of item: 0x02
          -----> item: 
               -----> variant, length of item
               -----> content of item

13, the last fout bytes in little endian is locktime: 00000000

Compare with p2pkh transaction the p2wpkh has three more fields: segwit marker, segwit flag, and witness. The field of witness contains tow fields: signathre and pubkey. And the scriptpubkey will contains
two parts one is instruction OP_0, the second is 20 bytes hash, therefore the combined sccript is as following:


![p2wpkh](https://github.com/user-attachments/assets/33eb3300-9e4f-479f-b403-1f28c6e972f7)

when executing the script, the the first instruction will push 0 onto the stack, then a 20 byte hash will push to stack at following:

![p2wpkh (1)](https://github.com/user-attachments/assets/1a951879-b6ed-4136-b1cb-603237856f9e)

For older version of fullnode that can not handle segwit transaction, it will stop here since there is nothing for the script, and the top element on the stack is not 0 and the result can be seen as 
success. Nodes capable of handing segwit transaction, it will notice the pattern that is OP_0 <20-byte hash>, it will take the pubkey and signature from witness field and reconstruct the script like
following:

![p2wpkh (2)](https://github.com/user-attachments/assets/aaaaa84e-b647-4cc6-a75a-0652fdfa1a30)

Now we can handle the script as before and when executing the OP_HASH160, we will put the hash result and the 20 byte hash both on to the stack, and if the OP_EQUALVERIFY will check their match and
the OP_CHECKSIG will check the signature is valid or not, if they are all success, there would be value 1 on the stack.

Let's see how to change the code of the transaction class to suppport p2wpkh transaction, in intput.go change the code as following:

```go
type TransactionInput struct {
	previousTransactionID    []byte
	previousTransactionIndex *big.Int
	scriptSig                *ScriptSig
	sequence                 *big.Int
	fetcher                  *TransactionFetcher
	//add new here
	witness [][]byte
}
```

Then in transaction.go, do the following:
```go
type Transaction struct {
	version   *big.Int
	txInputs  []*TransactionInput
	txOutputs []*TransactionOutput
	lockTime  *big.Int
	testnet   bool
	//add segwit field
	segwit bool
}

func getInputCount(bufReader *bufio.Reader) *big.Int {
	//we can remove the following, since we will handle it in parseSegwit
	// firstByte, err := bufReader.Peek(1)
	// if err != nil {
	// 	panic(err)
	// }

	// if firstByte[0] == 0x00 {
	// 	//skip the first two bytes
	// 	skipBuf := make([]byte, 2)
	// 	//_, err = bufReader.Read(skipBuf)
	// 	_, err = io.ReadFull(bufReader, skipBuf)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// }

	count := ReadVarint(bufReader)
	fmt.Printf("input count is: %x\n", count)
	return count
}

func ParseTransaction(binary []byte) *Transaction {
	reader := bytes.NewReader(binary)
	bufReader := bufio.NewReader(reader)

	verBuf := make([]byte, 4)
	//bufReader.Read(verBuf)
	io.ReadFull(bufReader, verBuf)

	segWitMarker := make([]byte, 1)
	io.ReadFull(bufReader, segWitMarker)

	reader = bytes.NewReader(binary)
	bufReader = bufio.NewReader(reader)
	if segWitMarker[0] == 0x00 {
		return parseSegwit(bufReader)
	}

	return parseLegacy(bufReader)
}

func parseLegacy(bufReader *bufio.Reader) *Transaction {
	transaction := &Transaction{}
	verBuf := make([]byte, 4)
	//bufReader.Read(verBuf)
	io.ReadFull(bufReader, verBuf)
	version := LittleEndianToBigInt(verBuf, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("transaction version:%x\n", version)
	transaction.version = version

	inputs := getInputCount(bufReader)
	transactionInputs := []*TransactionInput{}
	for i := 0; i < int(inputs.Int64()); i++ {
		input := NewTractionInput(bufReader)
		transactionInputs = append(transactionInputs, input)
	}
	transaction.txInputs = transactionInputs

	//read output counts
	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTractionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	//get last four bytes for lock time
	lockTimeBytes := make([]byte, 4)
	//bufReader.Read(lockTimeBytes)
	io.ReadFull(bufReader, lockTimeBytes)
	transaction.lockTime = LittleEndianToBigInt(lockTimeBytes, LITTLE_ENDIAN_4_BYTES)

	return transaction
}

func parseSegwit(bufReader *bufio.Reader) *Transaction {
	transaction := &Transaction{}
	transaction.segwit = true

	verBuf := make([]byte, 4)
	//bufReader.Read(verBuf)
	io.ReadFull(bufReader, verBuf)
	version := LittleEndianToBigInt(verBuf, LITTLE_ENDIAN_4_BYTES)
	fmt.Printf("transaction version:%x\n", version)
	transaction.version = version

	// check the following 2 bytes
	marker := make([]byte, 2)
	io.ReadFull(bufReader, marker)
	if marker[0] != 0x00 && marker[1] != 0x01 {
		panic("Not segwit transaction")
	}

	inputs := getInputCount(bufReader)
	transactionInputs := []*TransactionInput{}
	for i := 0; i < int(inputs.Int64()); i++ {
		input := NewTractionInput(bufReader)
		transactionInputs = append(transactionInputs, input)
	}
	transaction.txInputs = transactionInputs

	//read output counts
	outputs := ReadVarint(bufReader)
	transactionOutputs := []*TransactionOutput{}
	for i := 0; i < int(outputs.Int64()); i++ {
		output := NewTractionOutput(bufReader)
		transactionOutputs = append(transactionOutputs, output)
	}
	transaction.txOutputs = transactionOutputs

	//parsing witness data,
	for _, input := range transactionInputs {
		numItems := ReadVarint(bufReader)
		items := make([][]byte, 0)
		for i := 0; i < int(numItems.Int64()); i++ {
			itemLen := ReadVarint(bufReader)
			if itemLen.Int64() == 0 {
				items = append(items, []byte{})
			} else {
				item := make([]byte, itemLen.Int64())
				io.ReadFull(bufReader, item)
				items = append(items, item)
			}
		}
		input.witness = items
	}

	//get last four bytes for lock time
	lockTimeBytes := make([]byte, 4)
	//bufReader.Read(lockTimeBytes)
	io.ReadFull(bufReader, lockTimeBytes)
	transaction.lockTime = LittleEndianToBigInt(lockTimeBytes, LITTLE_ENDIAN_4_BYTES)

	return transaction
}
```
In the aboved code, when parsing the transaction binary data, we check the segwit marker, if marker is true, we goto parse segwit transaction, the only difference is that we need to add the parsing
for the witness data chunk, the data contains two object, one is signature the other is pubkey, let's run the aboved code as following:

```go
package main

import (
	"encoding/hex"
	"transaction"
)

func main() {
	txBinary, err := hex.DecodeString("0100000000010115e180dc28a2327e687facc33f10f2a20da717e5548406f7ae8b4c811072f8560100000000ffffffff0100b4f505000000001976a9141d7cd6c75c2e86f4cbf98eaed221b30bd9a0b92888ac02483045022100df7b7e5cda14ddf91290e02ea10786e03eb11ee36ec02dd862fe9a326bbcb7fd02203f5b4496b667e6e281cc654a2da9e4f08660c620a1051337fa8965f727eb19190121038262a6c6cec93c2d3ecd6c6072efea86d02ff8e3328bbd0242b20af3425990ac00000000")
	if err != nil {
		panic(err)
	}
	transaction.ParseTransaction(txBinary)
}
```

Now let's see how to verify the segwit transaction.



