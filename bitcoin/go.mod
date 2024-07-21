module main

go 1.19

replace elliptic_curve => ./elliptic-curve

replace transaction => ./transaction

replace networking => ./networking

replace merkletree => ./merkle-tree

replace bloomfilter => ./bloom-filter

require (
	bloomfilter v0.0.0-00010101000000-000000000000 // indirect
	networking v0.0.0-00010101000000-000000000000
)

require (
	elliptic_curve v0.0.0-00010101000000-000000000000 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/tsuna/endian v0.0.0-20151020052604-29b3a4178852 // indirect
	golang.org/x/crypto v0.25.0 // indirect
	golang.org/x/example/hello v0.0.0-20240716161537-39e772fc2670 // indirect
	merkletree v0.0.0-00010101000000-000000000000 // indirect
	transaction v0.0.0-00010101000000-000000000000 // indirect
)
