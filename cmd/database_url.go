package cmd

import (
	"fmt"
	"os"
	"strings"
)

// maxDatabaseURLFile bounds DATABASE_URL_FILE; a connection URL is far shorter.
const maxDatabaseURLFile = 4096

// databaseURL returns the shared store's URL: DATABASE_URL, or the contents of
// the file DATABASE_URL_FILE names, read once, so a mounted Secret never has
// to enter the environment. Setting both is refused, as is a file that is
// not a regular file, is empty or is over 4 KiB. The value is never logged
// or returned in an error. An empty result means the local SQLite store.
func databaseURL() (string, error) {
	inline, path := os.Getenv("DATABASE_URL"), os.Getenv("DATABASE_URL_FILE")
	switch {
	case path == "":
		return inline, nil
	case inline != "":
		return "", fmt.Errorf("set DATABASE_URL or DATABASE_URL_FILE, not both")
	}
	info, err := os.Stat(path) //nolint:gosec // G703: the operator names this file; reading it is the feature
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL_FILE: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("DATABASE_URL_FILE must name a regular file")
	}
	if info.Size() > maxDatabaseURLFile {
		return "", fmt.Errorf("DATABASE_URL_FILE is larger than %d bytes", maxDatabaseURLFile)
	}
	data, err := os.ReadFile(path) //nolint:gosec // G703: the operator names this file; reading it is the feature
	if err != nil {
		return "", fmt.Errorf("DATABASE_URL_FILE: cannot read the file")
	}
	url := strings.TrimSpace(string(data))
	if url == "" || len(data) > maxDatabaseURLFile {
		return "", fmt.Errorf("DATABASE_URL_FILE is empty or too large")
	}
	return url, nil
}

// sharedStoreConfigured reports whether a shared store is named at all, by
// either variable, without reading the file.
func sharedStoreConfigured() bool {
	return os.Getenv("DATABASE_URL") != "" || os.Getenv("DATABASE_URL_FILE") != ""
}
