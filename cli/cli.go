package cli

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
)

func Run(args []string) int {
	//todo
	encFlags := flag.NewFlagSet("enc", flag.ExitOnError)
	encIn := flag.Bool("stdin", false, "read from stdin instead of a file")
	encOut := flag.Bool("stdout", false, "write to stdout instead of a file")

	decFlags := flag.NewFlagSet("dec", flag.ExitOnError)
	decIn := flag.Bool("stdin", false, "read from stdin instead of file")
	decOut := flag.Bool("stdout", false, "write to stdout instead of a file")

	switch args[1] {
	case "enc":
		encFlags.Parse(args[2:])
		//todo
		sc := bufio.NewScanner(os.Stdin)
		var out *bufio.Writer

		plaintext := []byte{}

		if *encIn {
			fmt.Println("enter plaintext to encrypt")
			fmt.Print(">> ")
			for sc.Scan() {

				if err := sc.Err(); err != nil {
					log.Printf("error reading from stdin: %v\n", err)
				}
				data := []byte(sc.Text())
				plaintext = append(plaintext, data...)
			}
		} else {
			//todo
		}

		if *encOut {
			out = bufio.NewWriter(os.Stdout)
		}

	case "dec":
		decFlags.Parse(args[2:])
	}

	return 0
}
