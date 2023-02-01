package utils

import (
	"bufio"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/5amu/zeus/pkg/connections"
	"github.com/5amu/zeus/pkg/plugins"
)

// ValidateSinglePlugin is responsible for what it says. Basically it will
// launch plugins.NewPluginFromFile() and the plugins.Validate() functions
// returning possible errors
func ValidateSinglePlugin(path string) error {
	p, err := plugins.NewPluginFromFile(path)
	if err != nil {
		return err
	}
	err = plugins.Validate(p)
	if err != nil {
		return err
	}
	return nil
}

// ReadTargetsFromFile parses a target file and returns the list of parsed
// connection strings with relative errors if any
func ReadTargetsFromFile(fname string) ([]*connections.ConnectionString, error) {
	f, err := os.Open(fname)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		targets = append(targets, scanner.Text())
	}

	var ret []*connections.ConnectionString
	for _, target := range targets {
		cs, err := connections.NewConnectionString(target)
		if err != nil {
			return nil, err
		}
		ret = append(ret, cs)
	}
	return ret, scanner.Err()
}

// ReadTargetsFromString converts a string into a slice of connections.ConnectionString
func ReadTargetsFromString(target string) ([]*connections.ConnectionString, error) {
	if target == "" {
		return []*connections.ConnectionString{}, nil
	}
	cs, err := connections.NewConnectionString(target)
	if err != nil {
		return nil, err
	}
	return []*connections.ConnectionString{cs}, nil
}

// ReadPluginsFromDirectory will parse all yaml files in the provided directory
// and will return a list of yaml-unmarshaled plugins with relative errors if any
func ReadPluginsFromDirectory(path string) ([]*plugins.Plugin, error) {
	var toParse []string
	err := filepath.Walk(path, func(path string, info fs.FileInfo, err error) error {
		if !info.IsDir() {
			if strings.HasSuffix(info.Name(), ".yaml") {
				toParse = append(toParse, path)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var parsed []*plugins.Plugin
	for _, pluginFile := range toParse {
		p, err := plugins.NewPluginFromFile(pluginFile)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, p)
	}
	return parsed, nil
}
