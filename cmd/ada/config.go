package main

import (
	"errors"
	"fmt"
	"os"

	"sigs.k8s.io/yaml"

	"github.com/leomcl/ada/internal/sandbox"
)

const defaultConfigPath = "ada.yaml"

func loadConfig() (sandbox.Config, error) {
	cfg := sandbox.Defaults()

	path := os.Getenv("ADA_CONFIG")
	explicit := path != ""
	if !explicit {
		path = defaultConfigPath
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if !explicit && errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return sandbox.Config{}, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return sandbox.Config{}, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}
