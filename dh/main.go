// This program performs a Diffie-Hellman key exchange using NaCL.
package main

import (
	"crypto/rand"
	"fmt"

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
	box.Precompute(aShare, aPub, bPriv)

	bShare := &[32]byte{}
	box.Precompute(bShare, bPub, aPriv)

	fmt.Printf("a share %v\n", aShare)
	fmt.Printf("b share %v\n", bShare)

	aComm := &[32]byte{}
	box.Precompute(aComm, aShare, bPriv)

	bComm := &[32]byte{}
	box.Precompute(bComm, bShare, aPriv)
}
