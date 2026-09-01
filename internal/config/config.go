// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package config reads the monitor's runtime configuration from the
// environment the platform injects.
//
// Nothing a customer chooses lives here. The tenant, the service model,
// the callback allowlist and every credential arrive later through the
// attested configure call, over a channel whose certificate carries a
// hardware quote over the measurement of this build.
package config

import (
	"errors"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the process-level configuration.
type Config struct {
	// Port is the host-network port the platform assigned. Required:
	// there is no fallback, because a hard-coded port collides with a
	// co-located app and fails the readiness probe.
	Port int

	// DataDir is the per-app sealed volume. Its LUKS key is released to
	// the measured build at boot, so everything under it is encrypted at
	// rest under a key the host never sees.
	DataDir string

	// Name identifies this instance in checkpoints, reports and log
	// lines.
	Name string

	// Vantage names the observation point this instance speaks for. One
	// instance today; the field exists so a quorum of vantage points
	// needs no migration.
	Vantage string

	// ImageDigest is the workload measurement the platform injects. It
	// is stamped into every checkpoint and every report, so a reader
	// knows which build signed them.
	ImageDigest string

	// ManagerURL, ContainerName and ContainerToken are the in-enclave
	// SDK callback credentials. They are runtime secrets and are not
	// part of the attested spec.
	ManagerURL     string
	ContainerName  string
	ContainerToken string
	AppID          string

	// OIDC issuer and audience for end-user bearer tokens.
	Issuer   string
	Audience string

	// DevAuth accepts "dev:<sub>:<display>:<roles>" bearer tokens instead
	// of verifying against the identity provider. Local development and
	// tests only; refused when the platform callback credentials are
	// present, so it cannot be turned on by accident in an enclave.
	DevAuth bool

	// SelfConfigure brings a development instance up with a default
	// configuration instead of waiting for a configure call.
	SelfConfigure bool
	// Pack is a service-model pack to seed a self-configured instance
	// with.
	Pack string

	// CheckpointInterval is how often a quiet monitor anchors its state.
	CheckpointInterval time.Duration
	// RollupLag is how far behind the present the folder works, so it
	// only ever folds intervals that are closed.
	RollupLag time.Duration
}

// Load reads the environment.
func Load() (*Config, error) {
	c := &Config{
		DataDir:            env("MONITOR_DATA_DIR", "/data"),
		Name:               env("MONITOR_NAME", "monitor"),
		Vantage:            env("MONITOR_VANTAGE", ""),
		ImageDigest:        firstEnv("PRIVASYS_IMAGE_DIGEST", "IMAGE_DIGEST"),
		ManagerURL:         firstEnv("PRIVASYS_MANAGER_URL", "MANAGER_URL"),
		ContainerName:      firstEnv("PRIVASYS_CONTAINER_NAME", "CONTAINER_NAME"),
		ContainerToken:     firstEnv("PRIVASYS_CONTAINER_TOKEN", "CONTAINER_TOKEN"),
		AppID:              firstEnv("PRIVASYS_APP_ID", "APP_ID"),
		Issuer:             env("MONITOR_OIDC_ISSUER", "https://privasys.id"),
		Audience:           env("MONITOR_OIDC_AUDIENCE", "privasys-platform"),
		DevAuth:            truthy(os.Getenv("MONITOR_DEV_AUTH")),
		SelfConfigure:      truthy(os.Getenv("MONITOR_SELF_CONFIGURE")),
		Pack:               os.Getenv("MONITOR_PACK"),
		CheckpointInterval: duration("MONITOR_CHECKPOINT_INTERVAL", 6*time.Hour),
		RollupLag:          duration("MONITOR_ROLLUP_LAG", 90*time.Second),
	}
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil || port <= 0 || port > 65535 {
		return nil, errors.New("config: PORT must be set to the port the platform assigned")
	}
	c.Port = port

	if c.Vantage == "" {
		c.Vantage = c.Name
	}

	// Development shortcuts are refused inside an enclave. The manager
	// callback credentials only exist where the platform put them, so
	// their presence is the reliable signal.
	if c.ManagerURL != "" && c.ContainerToken != "" {
		c.DevAuth = false
		c.SelfConfigure = false
	}
	return c, nil
}

// OnPlatform reports whether the manager callback credentials are
// present, which is what distinguishes a real deployment from a
// developer's machine.
func (c *Config) OnPlatform() bool {
	return c.ManagerURL != "" && c.ContainerName != "" && c.ContainerToken != ""
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func truthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func duration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
