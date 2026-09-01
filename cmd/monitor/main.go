// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Command monitor watches a customer's service from inside a
// confidential VM.
//
// The order of boot matters and is worth reading once. The sealed
// volume is opened first, because the signing key and the credentials
// live there and nothing can be attested without them. The record is
// opened next, and the configuration a previous boot wrote is restored
// from it, which is what lets the process lift the platform's configure
// gate for itself instead of waiting for somebody to re-type a
// configuration that was never lost. Then the boot is written down,
// including the gap since the last one: a monitor that was not running
// did not see a service that was up, and the coverage figure in every
// report depends on that being recorded rather than assumed.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	// The zone database is compiled in. Agreed service time is expressed
	// in the customer's own timezone, and a monitor that cannot resolve
	// "Europe/Paris" cannot compute the denominator of the availability
	// formula.
	_ "time/tzdata"

	"github.com/Privasys/container-app-service-monitoring/internal/api"
	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/config"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/pack"
	"github.com/Privasys/container-app-service-monitoring/internal/platform"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
	"github.com/Privasys/container-app-service-monitoring/internal/webhook"
)

// version is stamped at build time.
var version = "dev"

// packDir is where the service models baked into the image live.
const packDir = "/packs"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(log); err != nil {
		log.Error("the monitor stopped", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("starting", "version", version, "name", cfg.Name, "vantage", cfg.Vantage,
		"data_dir", cfg.DataDir, "port", cfg.Port, "on_platform", cfg.OnPlatform())

	material, err := keys.Load(filepath.Join(cfg.DataDir, "keys"))
	if err != nil {
		return err
	}
	vault, err := secrets.Open(filepath.Join(cfg.DataDir, "secrets"), material.Master)
	if err != nil {
		return err
	}

	// The commitment key is derived from the sealed master secret. The
	// volume is the confidentiality boundary here, and deriving rather
	// than delivering removes a whole class of "the monitor came back
	// but cannot open its own record" failures on an unattended restart.
	ck, source, err := material.CommitmentKey(nil)
	if err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "record"), ck)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(); err != nil {
		return err
	}

	egress := journey.NewAllowlist()
	if !cfg.OnPlatform() && cfg.DevAuth {
		// A developer's target is whatever they just started. Inside an
		// enclave the platform credentials are present and this branch is
		// unreachable, so the allowlist is always closed where it counts.
		egress.Open()
		log.Warn("the outbound allowlist is open; this is a development mode and is refused on the platform")
	}

	mon := core.New(st, material, vault, egress, core.Options{
		Name: cfg.Name, Vantage: cfg.Vantage, ImageDigest: cfg.ImageDigest,
		CheckpointInterval: cfg.CheckpointInterval, CommitmentSource: source,
	})

	manager := platform.NewManager(cfg.ManagerURL, cfg.ContainerName, cfg.ContainerToken)
	roles, err := auth.NewDefaultModel()
	if err != nil {
		return err
	}
	var verifier auth.Verifier = auth.NewJWKSVerifier(cfg.Issuer, cfg.Audience)
	if cfg.DevAuth {
		verifier = auth.DevVerifier{}
		log.Warn("development authentication is enabled; tokens are not verified against the identity provider")
	}

	scheduler := probe.New(mon, log)
	scheduler.RollupLag = cfg.RollupLag
	scheduler.CheckpointInterval = cfg.CheckpointInterval

	sender := webhook.New(mon, material.Signer, material.KeyID, egress, log)
	mon.SetHooks(core.Hooks{OnAlert: sender.Enqueue})

	server := api.NewServer(log, mon, verifier, roles, scheduler)
	server.Version = version
	server.PackDir = packDir
	server.Manifest = readManifest(log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	server.Configure = func(document []byte) (any, error) {
		var req core.ConfigureRequest
		if len(document) > 0 {
			if err := json.Unmarshal(document, &req); err != nil {
				return nil, fmt.Errorf("configure: %w", err)
			}
		}
		result, err := mon.Configure(auth.System(req.Tenant), req, packDir)
		if err != nil {
			return nil, err
		}
		publishExtensions(ctx, log, manager, mon, material)
		return result, nil
	}

	// Self-recovery. The configuration is on the volume; the gate is the
	// runtime's and re-arms on every restart, so the process lifts it
	// itself rather than looking configuration-less to its owner.
	if _, restored, err := mon.LoadConfig(); err != nil {
		return err
	} else if restored {
		log.Info("restored the configuration from the sealed volume")
		if err := manager.ConfigComplete(ctx); err != nil {
			log.Error("could not lift the configure gate", "error", err)
		}
		publishExtensions(ctx, log, manager, mon, material)
	} else if cfg.SelfConfigure {
		if err := selfConfigure(mon, cfg); err != nil {
			return err
		}
		log.Info("self-configured for development")
	}

	recordBoot(log, mon, cfg)

	go scheduler.Run(ctx)
	go sender.Run(ctx)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprint(cfg.Port)),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = mon.RecordRuntimeEvent(model.EventShutdown, "the monitor is stopping")
		if _, err := mon.IssueCheckpoint(core.ReasonScheduled); err != nil {
			log.Error("could not anchor the state on shutdown", "error", err)
		}
		_ = srv.Shutdown(shutdown)
	}()

	log.Info("listening", "port", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// publishExtensions republishes the attested extensions.
//
// They live in the manager's memory, not on the volume, so they are
// gone after a restart even though the key and the record are not. A
// client that verifies the certificate to learn which key signed the
// evidence has to find the extension there every time.
func publishExtensions(ctx context.Context, log *slog.Logger, manager *platform.Manager,
	mon *core.Monitor, material *keys.Material) {
	if manager == nil {
		return
	}
	if err := manager.PublishSigningKey(ctx, material.PublicKey()); err != nil {
		log.Error("could not publish the signing key", "error", err)
	}
	if lineage, err := mon.Lineage(auth.System(mon.Config().Tenant)); err == nil && lineage != nil {
		if err := manager.PublishRoot(ctx, lineage.Root); err != nil {
			log.Error("could not publish the ledger root", "error", err)
		}
	}
}

// recordBoot writes the boot down, with the gap since the last one.
//
// This is the honesty the coverage figure rests on. A monitor that was
// not running did not observe a service that was up, and a gap in the
// readings is otherwise indistinguishable from a quiet period.
func recordBoot(log *slog.Logger, mon *core.Monitor, cfg *config.Config) {
	detail := "the monitor started"
	if last, err := mon.LastBoot(); err == nil && last != nil {
		gap := mon.Now() - last.At
		if gap > 0 {
			detail = fmt.Sprintf("the monitor started after %s away", humanDuration(gap))
		}
	}
	if err := mon.RecordRuntimeEvent(model.EventBoot, detail); err != nil {
		log.Error("could not record the boot", "error", err)
	}
	_ = cfg
}

func humanDuration(seconds int64) string {
	switch {
	case seconds >= 86400:
		return fmt.Sprintf("%d days", seconds/86400)
	case seconds >= 3600:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds >= 60:
		return fmt.Sprintf("%d minutes", seconds/60)
	default:
		return fmt.Sprintf("%d seconds", seconds)
	}
}

// selfConfigure brings a development instance up without a configure
// call. The platform credentials switch it off, so it cannot be reached
// inside an enclave.
func selfConfigure(mon *core.Monitor, cfg *config.Config) error {
	req := core.ConfigureRequest{Tenant: "dev"}
	dir := packDir
	if cfg.Pack != "" {
		if _, err := os.Stat(cfg.Pack); err == nil {
			raw, err := os.ReadFile(cfg.Pack)
			if err != nil {
				return err
			}
			if _, err := pack.Parse(raw); err != nil {
				return err
			}
			req.Pack = raw
		} else {
			req.PackRef = cfg.Pack
			if _, err := os.Stat(packDir); err != nil {
				dir = "packs"
			}
		}
	}
	_, err := mon.Configure(auth.System("dev"), req, dir)
	return err
}

// readManifest loads the app manifest baked into the image, which is
// what the platform reads to learn the tool surface and the configure
// gate.
func readManifest(log *slog.Logger) []byte {
	for _, path := range []string{"/privasys.json", "privasys.json"} {
		if raw, err := os.ReadFile(path); err == nil {
			return raw
		}
	}
	log.Warn("no app manifest was found; the tool surface will not be advertised")
	return nil
}
