package server

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestECDSAJWKValidatedPoints(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			private, err := ecdsa.GenerateKey(curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := private.PublicKey.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			size := (len(encoded) - 1) / 2
			key := jwkKey{Crv: curve.Params().Name,
				X: base64.RawURLEncoding.EncodeToString(encoded[1 : 1+size]),
				Y: base64.RawURLEncoding.EncodeToString(encoded[1+size:])}
			parsed, err := ecdsaPublicKeyFromJWK(key)
			if err != nil {
				t.Fatal(err)
			}
			got, err := parsed.Bytes()
			if err != nil || !bytes.Equal(got, encoded) {
				t.Fatal("JWK round-trip changed the public key")
			}
			digest := sha256.Sum256([]byte("synthetic JWK verification"))
			signature, err := ecdsa.SignASN1(rand.Reader, private, digest[:])
			if err != nil || !ecdsa.VerifyASN1(parsed, digest[:], signature) {
				t.Fatal("parsed JWK cannot verify a valid signature")
			}
			padded := key
			padded.X = base64.RawURLEncoding.EncodeToString(append([]byte{0}, encoded[1:1+size]...))
			if _, err := ecdsaPublicKeyFromJWK(padded); err != nil {
				t.Fatal("previously accepted leading-zero coordinate rejected", err)
			}
			for _, invalid := range []jwkKey{
				{Crv: key.Crv, X: "AA", Y: "AA"},
				{Crv: key.Crv, X: base64.RawURLEncoding.EncodeToString(curve.Params().P.Bytes()), Y: key.Y},
				{Crv: key.Crv, X: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{255}, size+1)), Y: key.Y},
				{Crv: key.Crv, X: "!", Y: key.Y},
				{Crv: key.Crv, X: key.X},
				{Crv: "P-999", X: key.X, Y: key.Y},
			} {
				if _, err := ecdsaPublicKeyFromJWK(invalid); err == nil {
					t.Fatal("accepted malformed or off-curve public key")
				}
			}
		})
	}
}
