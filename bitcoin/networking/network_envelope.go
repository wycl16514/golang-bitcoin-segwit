package networking

import (
	"bufio"
	"bytes"
	ecc "elliptic_curve"
	"fmt"
	"io"
	"math/big"
	tx "transaction"
)

/*
packet: 1, header , payload

f9beb4d9
76657273696f6e0000000000

65000000

5f1a69d2

721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001

1, first 4 bytes we call the magic number: f9beb4d9-> mainnet
it is used to tell the receiver that, here is the beginning of a network packet,
for testnet: 0b110907

2, the following 12 bytes is the command of the packet:76657273696f6e0000000000
actually it is humman readable string, string(76657273696f6e0000000000)
command is used to indicate the purpose of this packet

3, 65000000 the length of the payload, little endian => 00 00 00 65

4, the following 4 bytes is the first 4 bytes of hash256 of the payload: 5f1a69d2

5, the remaining data is payload
*/

type NetworkEnvelope struct {
	command []byte
	payload []byte
	testnet bool
	magic   []byte
}

func NewNetworkEnvelope(command []byte, payload []byte, testnet bool) *NetworkEnvelope {
	network := &NetworkEnvelope{
		command: command,
		payload: payload,
		testnet: testnet,
	}

	if testnet {
		network.magic = []byte{0x0b, 0x11, 0x09, 0x07}
	} else {
		network.magic = []byte{0xf9, 0xbe, 0xb4, 0xd9}
	}

	return network
}

func ParseNetwork(rawData []byte, testnet bool) *NetworkEnvelope {
	reader := bytes.NewReader(rawData)
	bufReader := bufio.NewReader(reader)

	magic := make([]byte, 4)
	n, err := io.ReadFull(bufReader, magic)
	if err != nil {
		panic(err)
	}
	if n == 0 {
		panic("connection reset")
	}

	var expectedMagic []byte
	if testnet {
		expectedMagic = []byte{0x0b, 0x11, 0x09, 0x07}
	} else {
		expectedMagic = []byte{0xf9, 0xbe, 0xb4, 0xd9}
	}
	if !bytes.Equal(magic, expectedMagic) {
		panic("magic is not right")
	}

	command := make([]byte, 12)
	_, err = io.ReadFull(bufReader, command)
	if err != nil {
		panic(err)
	}

	payloadLenBuf := make([]byte, 4)
	_, err = io.ReadFull(bufReader, payloadLenBuf)
	if err != nil {
		panic(err)
	}
	payLoadLen := new(big.Int)
	payLoadLen.SetBytes(tx.ReverseByteSlice(payloadLenBuf))

	checksum := make([]byte, 4)
	_, err = io.ReadFull(bufReader, checksum)
	if err != nil {
		panic(err)
	}

	payload := make([]byte, payLoadLen.Int64())
	_, err = io.ReadFull(bufReader, payload)
	if err != nil {
		panic(err)
	}

	calculatedChecksum := ecc.Hash256(string(payload))[0:4]
	if !bytes.Equal(checksum, calculatedChecksum) {
		panic("checksum dose not match")
	}

	return NewNetworkEnvelope(command, payload, testnet)
}

func (n *NetworkEnvelope) Serialize() []byte {
	result := make([]byte, 0)
	result = append(result, n.magic...)
	/*
		command field needs to be 12 bytes long, if it is not enough, we will padding
		it with 0x00
	*/
	command := make([]byte, 0)
	command = append(command, n.command...)
	commandLen := len(command)
	if len(command) < 12 {
		for i := 0; i < 12-commandLen; i++ {
			command = append(command, 0x00)
		}
	}
	result = append(result, command...)

	payoadLen := big.NewInt(int64(len(n.payload)))
	result = append(result, tx.BigIntToLittleEndian(payoadLen, tx.LITTLE_ENDIAN_4_BYTES)...)
	//checksum
	result = append(result, ecc.Hash256(string(n.payload))[0:4]...)
	result = append(result, n.payload...)

	return result
}

func (n *NetworkEnvelope) String() string {
	return fmt.Sprintf("%s : %x\n", string(n.command), n.payload)
}

/*
raw data for version command:
7f110100

0000000000000000

ad17835b00000000

0000000000000000

00000000000000000000ffff00000000

8d20

0000000000000000

00000000000000000000ffff00000000

8d20

f6a8d7a440ec27a1

1b

2f70726f6772616d6d696e67626c6f636b636861696e3a302e312f

00000000

01

1, the first 4 bytes is version number of the node, it in little edian, 7f110100=70015

2, the following 8 bytes: 0000000000000000 is network service of sender , little endian

3, the following 8 byts:ad17835b00000000, unix timestamp of the sender

4, the following 8 bytes:0000000000000000 in little endian,  the service of the receiver,

5, the following 16 bytes: 00000000000000000000ffff 00000000 it is ip of receiver,
mapping ip4 => ip6, 00000000000000000000ffff => telling the sender is in ip4 format
00. 00 .00. 00 => ip

6. the following 2 bytes: 8d20, it is port of sender, 8333 is default port for bitcoin node
of mainnet, if the node is on the testnet, 18333

7, the following 8 bytes: 0000000000000000 in little edian it is network service of sender

8, the following 16 bytes: 00000000000000000000ffff00000000, ip of sender
00000000000000000000ffff => ip4, 00000000 => 0.0.0.0

9. the following 2 bytes => port of sender 8d20=>8333

10. nonce f6a8d7a440ec27a1, it is used to detect connection to itself

11. 1b it is length of the following data chunk which is  an varint int length

12, the following data chunk with the given length aboved is user agent:
2f70726f6772616d6d696e67626c6f636b636861696e3a302e312f
actually is a string content,

13, the following 4 bytes is the number of latest block in this node 00000000

14, the final byte is relay, 01=> relay is true, otherwise relay is false

when a node first setup and running , it will get a set of friends by p2p protocol
but the peer it wants to find may not in the set of friends,

Bob frineds: Jim and Tom
but Bob want to find Alice

if Alice is a friend of Tom
Bob will send packets to Jim and Tom together,
then Tom will relay the packet to Alice
*/
