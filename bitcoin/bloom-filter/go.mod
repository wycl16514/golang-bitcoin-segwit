module bloomfilter

replace transaction => ../transaction

go 1.19

require (
	github.com/spaolacci/murmur3 v1.1.0
	transaction v0.0.0-00010101000000-000000000000
)

require github.com/tsuna/endian v0.0.0-20151020052604-29b3a4178852 // indirect
