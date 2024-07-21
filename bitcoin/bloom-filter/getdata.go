package bloomfilter

import (
	"math/big"
	"transaction"
)

// data => item
type Data struct {
	dataType   []byte
	identifier []byte
}

type GetDataMessage struct {
	command string
	data    []Data
}

func NewGetDataMessage() *GetDataMessage {
	getDataMsg := &GetDataMessage{
		command: "getdata",
		data:    make([]Data, 0),
	}

	return getDataMsg
}

func (g *GetDataMessage) AddData(dataType []byte, identifier []byte) {
	g.data = append(g.data, Data{
		dataType:   dataType,
		identifier: identifier,
	})
}

func (g *GetDataMessage) Command() string {
	return g.command
}

func (g *GetDataMessage) Serialize() []byte {
	result := make([]byte, 0)
	dataCount := big.NewInt(int64(len(g.data)))
	result = append(result, transaction.EncodeVarint(dataCount)...)

	for _, item := range g.data {
		dataType := new(big.Int)
		dataType.SetBytes(item.dataType)
		result = append(result, transaction.BigIntToLittleEndian(dataType,
			transaction.LITTLE_ENDIAN_4_BYTES)...)
		result = append(result, transaction.ReverseByteSlice(item.identifier)...)
	}

	return result
}
