package cmd

import (
	"fmt"
	"os"

	"github.com/sgaunet/template-cli/internal/aes"
	"github.com/spf13/cobra"
)

// setCmd represents the set command
var decCmd = &cobra.Command{
	Use:   "dec",
	Short: "decrypt file in AES 128/256/512",
	Long:  `decrypt file in AES 128/256/512`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			tmpFile               *os.File
			overwriteOriginalFile bool
			err                   error
		)

		if inputFile == "" {
			fmt.Fprintf(os.Stderr, "inputfile not specified\n")
			_ = cmd.Help()
			os.Exit(1)
		}

		if !isFileExists(inputFile) {
			fmt.Fprintf(os.Stderr, "File %s does not exist\n", inputFile)
			os.Exit(1)
		}

		if outputFile == "" {
			overwriteOriginalFile = true
			tmpFile, err = os.CreateTemp("/tmp", "gocrypt")
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot create temp file\n")
				os.Exit(1)
			}
			outputFile = tmpFile.Name()
			tmpFile.Close()
		}

		if isFileExists(outputFile) && !overwriteOriginalFile {
			err = os.Remove(outputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot remove file %s\n", outputFile)
				os.Exit(1)
			}
		}

		key, err := aes.GetKey(keyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err.Error())
			os.Exit(1)
		}

		err = aes.DecryptFile(key, inputFile, outputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err.Error())
			os.Exit(1)
		}

		if overwriteOriginalFile {
			// rename tmp file to original file
			err = os.Rename(outputFile, inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err.Error())
				os.Exit(1)
			}
		}

		if rmOption && !overwriteOriginalFile {
			err = os.Remove(inputFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err.Error())
				os.Exit(1)
			}
		}
	},
}
