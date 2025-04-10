package cmd

import "os"

func isFileExists(file string) bool {
	f, err := os.Open(file) //nolint:gosec
	if os.IsNotExist(err) {
		return false
	}
	defer f.Close() //nolint:errcheck
	i, _ := os.Stat(file)
	return !i.IsDir()
}
