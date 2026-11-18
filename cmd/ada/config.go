package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"sigs.k8s.io/yaml"

	"github.com/leomcl/ada/internal/sandbox"
)

const defaultConfigPath = "ada.yaml"

func loadConfig(path string) (sandbox.Config, error) {
	cfg := sandbox.Defaults()
	if ts := os.Getenv("TS_AUTHKEY"); ts != "" {
		cfg.TailscaleAuthKey = ts
	}

	explicit := path != ""
	if !explicit {
		if envPath := os.Getenv("ADA_CONFIG"); envPath != "" {
			path = envPath
			explicit = true
		} else {
			path = defaultConfigPath
		}
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

func findConfigFlag(args []string) string {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if val, ok := strings.CutPrefix(arg, "--config="); ok {
			return val
		}
		if val, ok := strings.CutPrefix(arg, "-config="); ok {
			return val
		}
		if (arg == "--config" || arg == "-config") && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
