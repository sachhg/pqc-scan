// Fixture: Go module declaring quantum-vulnerable dependencies (PQC014).
module example.com/fixture

go 1.22

require (
	github.com/golang-jwt/jwt/v5 v5.2.1
	github.com/btcsuite/btcd/btcec/v2 v2.3.4
	golang.org/x/crypto v0.24.0
	github.com/stretchr/testify v1.9.0 // indirect
)

require github.com/dgrijalva/jwt-go v3.2.0+incompatible

replace github.com/some/forked v1.0.0 => ./vendor/forked
