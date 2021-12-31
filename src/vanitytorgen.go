/*

	MIT License

	Copyright (c) 2021 kexkey

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

*/

package main

import (
	"bytes"
	"encoding/base32"
	"fmt"
	"os"
	"path"
	"strings"
	"time"

	"crypto/ed25519"
	"crypto/sha512"

	"golang.org/x/crypto/sha3"
)

func main() {

	pathname := "."
	if len(os.Args) < 2 {
		fmt.Println("torgenvanity")
		fmt.Println("Usage: torgenvanity <prefix> [path]")
		fmt.Println()
		fmt.Println("Will generate Tor keys until corresponding onion address starts with <prefix>")
		fmt.Println("When found, hs_ed25519_secret_key, hs_ed25519_public_key and")
		fmt.Println("hostname files will be created in the given path location or")
		fmt.Println("in current directory if path is not supplied.")
		os.Exit(0)
	} else if len(os.Args) == 3 {
		pathname = path.Clean(os.Args[2])
	}

	var i int64 = 0
	startTime := time.Now()
	startswith := os.Args[1]
	fmt.Println("Matching prefix: " + startswith)
	fmt.Println("Destination path: " + pathname)
	fmt.Printf("Start time: %s\r\n", startTime)

	fmt.Println("Press ctrl-c to abort")
	fmt.Println()

	/**
		About the key files format: https://gitweb.torproject.org/tor.git/tree/src/lib/crypt_ops/crypto_format.c?h=tor-0.4.1.6#n34

		Write the <b>datalen</b> bytes from <b>data</b> to the file named
		<b>fname</b> in the tagged-data format.  This format contains a
		32-byte header, followed by the data itself.  The header is the
		NUL-padded string "== <b>typestring</b>: <b>tag</b> ==".  The length
		of <b>typestring</b> and <b>tag</b> must therefore be no more than
		24.

		About the secret key format: https://gitweb.torproject.org/tor.git/tree/src/lib/crypt_ops/crypto_ed25519.h?h=tor-0.4.1.6#n29

		Note that we store secret keys in an expanded format that doesn't match
		the format from standard ed25519.  Ed25519 stores a 32-byte value k and
		expands it into a 64-byte H(k), using the first 32 bytes for a multiplier
		of the base point, and second 32 bytes as an input to a hash function
		for deriving r.  But because we implement key blinding, we need to store
		keys in the 64-byte expanded form.
	**/

	for {
		// Key pair generation
		publicKey, privateKey, _ := ed25519.GenerateKey(nil)

		// From https://github.com/rdkr/oniongen-go
		// checksum = H(".onion checksum" || pubkey || version)
		var checksumBytes bytes.Buffer
		checksumBytes.Write([]byte(".onion checksum"))
		checksumBytes.Write([]byte(publicKey))
		checksumBytes.Write([]byte{0x03})
		checksum := sha3.Sum256(checksumBytes.Bytes())

		// onion_address = base32(pubkey || checksum || version)
		var onionAddressBytes bytes.Buffer
		onionAddressBytes.Write([]byte(publicKey))
		onionAddressBytes.Write([]byte(checksum[:2]))
		onionAddressBytes.Write([]byte{0x03})
		onionAddress := strings.ToLower(base32.StdEncoding.EncodeToString(onionAddressBytes.Bytes()))

		// Simple display every 10000 generations to avoir slowering processing...
		if i%10000 == 0 {
			fmt.Printf("\r %d %s %s", i, time.Now(), onionAddress)
		}
		i++

		if strings.HasPrefix(onionAddress, startswith) {
			// For stats summary
			endTime := time.Now()
			fmt.Printf("\r %d %s %s", i, endTime, onionAddress)
			fmt.Println()
			fmt.Println()
			elapsed := endTime.Sub(startTime).Seconds()
			fmt.Printf("%d attempts in %f seconds: %f attempts/s\r\n", i, elapsed, float64(i)/elapsed)
			fmt.Println()

			// Convert seed to expanded private key...
			// Ref.: https://gitweb.torproject.org/tor.git/tree/src/ext/ed25519/donna/ed25519_tor.c?h=tor-0.4.1.6#n61
			// Ref.: https://gitweb.torproject.org/tor.git/tree/src/ext/curve25519_donna/README?h=tor-0.4.1.6#n28
			fmt.Println("Converting keys for Tor...")
			h := sha512.Sum512(privateKey[:32])
			h[0] &= 248
			h[31] &= 127
			h[31] |= 64

			// Create the Tor Hidden Service private key file
			fmt.Println("Creating secret file...")
			var fileBytes bytes.Buffer
			fileBytes.Write([]byte("== ed25519v1-secret: type0 =="))
			fileBytes.Write(bytes.Repeat([]byte{0x00}, 3))
			fileBytes.Write(h[:])

			prvFile, err := os.Create(pathname + "/hs_ed25519_secret_key")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			_, err = fileBytes.WriteTo(prvFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			err = prvFile.Close()

			// Create the Tor Hidden Service public key file
			fmt.Println("Creating public file...")
			fileBytes.Reset()
			fileBytes.Write([]byte("== ed25519v1-public: type0 =="))
			fileBytes.Write(bytes.Repeat([]byte{0x00}, 3))
			fileBytes.Write([]byte(publicKey))

			pubFile, err := os.Create(pathname + "/hs_ed25519_public_key")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			_, err = fileBytes.WriteTo(pubFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			pubFile.Close()

			// Create the Tor Hidden Service hostname file
			fmt.Println("Creating onion address file...")
			nameFile, err := os.Create(pathname + "/hostname")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			_, err = nameFile.WriteString(strings.ToLower(onionAddress) + ".onion\n")
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			nameFile.Close()

			break
		}
	}

	fmt.Println("Done!")
}
