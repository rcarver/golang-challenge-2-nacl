// This program attempts to do a Diffie-Hellman key exchange using NaCL.
package main

import (
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

func main() {

	fmt.Printf("Key pairs\n")

	aPub, aPriv, _ := box.GenerateKey(rand.Reader)
	bPub, bPriv, _ := box.GenerateKey(rand.Reader)

	fmt.Printf("a pub  %v\n", aPub)
	fmt.Printf("a priv %v\n", aPriv)
	fmt.Printf("b pub  %v\n", bPub)
	fmt.Printf("b priv %v\n", bPriv)

	fmt.Printf("\n")
	fmt.Printf("Shared keys\n")

	aShare := &[32]byte{}
	Compute(aShare, aPub, aPriv)

	bShare := &[32]byte{}
	Compute(bShare, bPub, bPriv)

	fmt.Printf("a share %v\n", aShare)
	fmt.Printf("b share %v\n", bShare)

	aComm := &[32]byte{}
	Compute(aComm, aPriv, bShare)

	bComm := &[32]byte{}
	Compute(bComm, bPriv, aShare)

	fmt.Printf("\n")
	fmt.Printf("Common keys\n")

	fmt.Printf("a comm %v\n", aComm)
	fmt.Printf("b comm %v\n", bComm)

}

var zeros [16]byte

// This is box.Precompute for playing with.
func Compute(sharedKey, peersPublicKey, privateKey *[32]byte) {
	curve25519.ScalarMult(sharedKey, privateKey, peersPublicKey)
	//salsa.HSalsa20(sharedKey, &zeros, sharedKey, &salsa.Sigma)
}
