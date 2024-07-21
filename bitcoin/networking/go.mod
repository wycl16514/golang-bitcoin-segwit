module networking

replace transaction => ../transaction

replace elliptic_curve => ../elliptic-curve

replace merkletree => ../merkle-tree

replace bloomfilter => ../bloom-filter

go 1.19

require (
	bloomfilter v0.0.0-00010101000000-000000000000
	elliptic_curve v0.0.0-00010101000000-000000000000
	merkletree v0.0.0-00010101000000-000000000000
	transaction v0.0.0-00010101000000-000000000000
)

require (
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tsuna/endian v0.0.0-20151020052604-29b3a4178852 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/example/hello v0.0.0-20240716161537-39e772fc2670 // indirect
)
