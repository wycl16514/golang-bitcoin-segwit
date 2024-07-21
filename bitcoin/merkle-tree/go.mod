module merkletree

replace elliptic_curve => ../elliptic-curve

replace transaction => ../transaction

go 1.19

require (
	elliptic_curve v0.0.0-00010101000000-000000000000
	transaction v0.0.0-00010101000000-000000000000
)

require (
	github.com/tsuna/endian v0.0.0-20151020052604-29b3a4178852 // indirect
	golang.org/x/crypto v0.25.0 // indirect
)
