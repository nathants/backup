// Package testkeys adapts single-generation test fixtures to the shared key APIs.
// It must never be imported by production packages.
package testkeys

import "github.com/nathants/go-libsodium"

func Chains(keys ...[]byte) libsodium.KeyChains {
	chains := make(libsodium.KeyChains, len(keys))
	for i, key := range keys {
		chains[i] = [][]byte{key}
	}
	return chains
}

func Ring(keys ...[]byte) *libsodium.Keyring {
	libsodium.Init()
	ring, err := libsodium.NewKeyring(keys)
	if err != nil {
		panic(err)
	}
	return ring
}
