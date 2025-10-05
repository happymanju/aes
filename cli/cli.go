package cli

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/happymanju/aes/pkg"
)

func Run(args []string) int {
	//todo
	encFlags := flag.NewFlagSet("enc", flag.ExitOnError)

	decFlags := flag.NewFlagSet("dec", flag.ExitOnError)

	var plaintext []byte
	var ciphertext []byte

	var password string

	switch args[1] {
	case "enc":
		encFlags.Parse(args[2:])
		sc := bufio.NewScanner(os.Stdin)

		for sc.Scan() {
			fmt.Printf("password >> ")
			t := strings.TrimSpace(sc.Text())

			if t != "" {
				password = t
				break
			} else {
				fmt.Println("")
				continue
			}
		}

		inFile, err := os.Open(filepath.Clean(encFlags.Arg(0)))
		if err != nil {
			log.Printf("error opening from %q: %v\n", encFlags.Arg(0), err)
			return 1
		}
		defer inFile.Close()

		data, err := io.ReadAll(inFile)
		if err != nil {
			log.Printf("error reading file %q: %v\n", encFlags.Arg(0), err)
			return 1
		}

		ciphertext, err = pkg.EncryptWithPassword(data, []byte(password))
		if err != nil {
			log.Printf("error encrypting: %v\n", err)
			return 1
		}

		outFile, err := os.Create(filepath.Clean(encFlags.Arg(1)))
		if err != nil {
			log.Printf("error creating file %q: %v\n", encFlags.Arg(1), err)
		}
		defer outFile.Close()

		n, err := outFile.Write(ciphertext)
		if err != nil {
			log.Printf("error writing to file: %v\n", err)
			return 1
		}
		fmt.Printf("Wrote %d bytes to %q\n", n, outFile.Name())
		return 0

	case "dec":
		decFlags.Parse(args[2:])
	}

	return 0
}
