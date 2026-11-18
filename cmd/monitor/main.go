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
	"strings"
	"syscall"
	"time"

	// The zone database is compiled in. Agreed service time is expressed
	// in the customer's own timezone, and a monitor that cannot resolve
	// "Europe/Paris" cannot compute the denominator of the availability
	// formula.
	_ "time/tzdata"

	"github.com/Privasys/container-app-service-monitoring/internal/api"
	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/clock"
	"github.com/Privasys/container-app-service-monitoring/internal/clock/timesource"
	"github.com/Privasys/container-app-service-monitoring/internal/config"
	"github.com/Privasys/container-app-service-monitoring/internal/core"
	"github.com/Privasys/container-app-service-monitoring/internal/journey"
	"github.com/Privasys/container-app-service-monitoring/internal/keys"
	"github.com/Privasys/container-app-service-monitoring/internal/mail"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/oncall"
	"github.com/Privasys/container-app-service-monitoring/internal/pack"
	"github.com/Privasys/container-app-service-monitoring/internal/platform"
	"github.com/Privasys/container-app-service-monitoring/internal/probe"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
	"github.com/Privasys/container-app-service-monitoring/internal/tenancy"
	"github.com/Privasys/container-app-service-monitoring/internal/webhook"
)

// version is stamped at build time.
var version = "dev"

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
	openEgress := !cfg.OnPlatform() && cfg.DevAuth
	if openEgress {
		// A developer's target is whatever they just started. Inside an
		// enclave the platform credentials are present and this branch is
		// unreachable, so the allowlist is always closed where it counts.
		egress.Open()
		log.Warn("the outbound allowlist is open; this is a development mode and is refused on the platform")
	}

	mon := core.New(st, material, vault, egress, core.Options{
		Name: cfg.Name, Vantage: cfg.Vantage, ImageDigest: cfg.ImageDigest,
		DataDir:            cfg.DataDir,
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

	// The platform clock. Every instance can derive its key; only one
	// configured for it ever turns it on.
	clockKey, err := material.ClockKey()
	if err != nil {
		return err
	}
	egressID := clock.NewEgressIdentity(cfg.ManagerURL, cfg.ContainerToken)
	clockSvc := clock.NewService(mon, clock.NewSigner(clockKey), timesource.New(),
		clock.RATLSFactory(egressID), log)

	// One monitor per app, beside the instance's own. Each opens its own
	// record under its own key; nothing here runs until Start.
	appRoles, err := auth.NewAppModel()
	if err != nil {
		return err
	}
	// republish is set once the context exists; the host calls it after
	// removing the monitor of an app the platform deleted.
	republish := func() {}

	// The mail credential is generated on the sealed volume once. Mail
	// starts working when its public certificate is on the registration;
	// until then each attempt is recorded as failed and the wallet still
	// reaches people.
	mailCred, err := mail.LoadCredential(filepath.Join(cfg.DataDir, "mail"), time.Now())
	if err != nil {
		return err
	}
	mailSender := &mail.Sender{TenantID: cfg.MailTenant, ClientID: cfg.MailClient, Credential: mailCred}
	// platformAPI is set once the configuration is restored, before any
	// app's monitor opens.
	var platformAPI *clock.Platform
	hostRef := new(*tenancy.Host)
	host := tenancy.New(tenancy.Options{
		Dir: filepath.Join(cfg.DataDir, "tenants"), Material: material,
		Base: core.Options{
			Name: cfg.Name, Vantage: cfg.Vantage, ImageDigest: cfg.ImageDigest,
			CheckpointInterval: cfg.CheckpointInterval, CommitmentSource: keys.SourceDerived,
		},
		PackDir: cfg.PackDir, OpenEgress: openEgress,
		Configure: func(t *tenancy.Tenant) {
			t.Scheduler.RollupLag = cfg.RollupLag
			t.Scheduler.CheckpointInterval = cfg.CheckpointInterval
			wireOnCall(t, log, hostRef, platformAPI, mon, func(ctx context.Context, to, subject, body string) error {
				return mailSender.Send(ctx, cfg.MailFrom, to, subject, body)
			})
		},
		Changed: func() { republish() },
		IsSelf:  tenancy.ResolvesToLoopback,
	}, log)

	*hostRef = host

	server := api.NewServer(log, mon, verifier, roles, scheduler)
	server.MailCert = &api.MailCertificate{
		Certificate: string(mailCred.CertificatePEM()), Thumbprint: mailCred.Thumbprint(),
		NotAfter: mailCred.NotAfter().UTC().Format(time.RFC3339),
	}
	if cfg.AppID != "" && !cfg.DevAuth {
		server.FormAnswers = auth.NewJWKSVerifier(cfg.Issuer, "app-form:"+cfg.AppID)
	}
	server.Version = version
	server.PackDir = cfg.PackDir
	server.Manifest = readManifest(log)
	server.Clock = clockSvc
	server.Tenants = host
	server.AppRoles = appRoles

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	republish = func() { publishExtensions(ctx, log, manager, mon, material, host) }
	server.TenantsChanged = republish

	server.Configure = func(document []byte) (any, error) {
		var req core.ConfigureRequest
		if len(document) > 0 {
			if err := json.Unmarshal(document, &req); err != nil {
				return nil, fmt.Errorf("configure: %w", err)
			}
		}
		result, err := mon.Configure(auth.System(req.Tenant), req, cfg.PackDir)
		if err != nil {
			return nil, err
		}
		clockSvc.Apply(mon.PlatformClockConfig())
		publishExtensions(ctx, log, manager, mon, material, host)
		publishClockKey(ctx, log, manager, clockSvc)
		// Start watching what was just configured, rather than at the
		// scheduler's next reload: that delay would be a coverage gap in
		// the first period, and one we caused.
		scheduler.Reload()
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
		clockSvc.Apply(mon.PlatformClockConfig())
		publishExtensions(ctx, log, manager, mon, material, host)
		publishClockKey(ctx, log, manager, clockSvc)
	} else if cfg.SelfConfigure {
		if err := selfConfigure(mon, cfg); err != nil {
			return err
		}
		log.Info("self-configured for development")
	}

	recordBoot(log, mon)

	go scheduler.Run(ctx)
	go sender.Run(ctx)

	if pc := mon.PlatformClockConfig(); pc != nil && pc.ManagementURL != "" && egressID != nil {
		platformAPI = clock.NewPlatform(pc.ManagementURL, clock.IdentityFrom(egressID), time.Now)
	}
	if err := host.Start(ctx); err != nil {
		return err
	}
	if len(host.List()) > 0 {
		publishExtensions(ctx, log, manager, mon, material, host)
	}
	startAppSync(ctx, log, host, platformAPI)

	srv := &http.Server{
		Addr:              net.JoinHostPort("", fmt.Sprint(cfg.Port)),
		Handler:           server.Handler(),
		ReadHeaderTimeout: 15 * time.Second,
	}
	// stopped closes once everything that writes to the record has
	// stopped. The record is closed (deferred above) only after it: the
	// server returns from ListenAndServe as soon as shutdown begins, not
	// when it ends.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// The clock first: no new background polls, the ones in flight
		// cancelled and waited for, and nothing it writes after this.
		clockSvc.Shutdown()
		_ = mon.RecordRuntimeEvent(model.EventShutdown, "the monitor is stopping")
		if _, err := mon.IssueCheckpoint(core.ReasonScheduled); err != nil {
			log.Error("could not anchor the state on shutdown", "error", err)
		}
		_ = srv.Shutdown(shutdown)
		// The apps' monitors after the server: a request still in
		// flight may be writing to one of them.
		host.Close()
	}()

	log.Info("listening", "port", cfg.Port)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	<-stopped
	return nil
}

// publishExtensions republishes the attested extensions.
//
// They live in the manager's memory, not on the volume, so they are
// gone after a restart even though the key and the record are not. A
// client that verifies the certificate to learn which key signed the
// evidence has to find the extension there every time.
//
// The ledger root is the instance's own record's root. On an instance
// that also hosts apps' monitors it is instead one digest over every
// record's state, the instance's own included (see tenancy.Host.Roots),
// so a handshake still pins all of them at once.
func publishExtensions(ctx context.Context, log *slog.Logger, manager *platform.Manager,
	mon *core.Monitor, material *keys.Material, host *tenancy.Host) {
	if manager == nil {
		return
	}
	if err := manager.PublishSigningKey(ctx, material.PublicKey()); err != nil {
		log.Error("could not publish the signing key", "error", err)
	}
	lineage, err := mon.Lineage(auth.System(mon.Config().Tenant))
	if err != nil || lineage == nil {
		return
	}
	root := lineage.Root
	if host != nil && len(host.List()) > 0 {
		own := fmt.Sprintf("%s %s %d", mon.Config().Tenant, lineage.Root, lineage.Version)
		if root, err = host.Roots(own); err != nil {
			log.Error("could not summarise the apps' records", "error", err)
			return
		}
	}
	if err := manager.PublishRoot(ctx, root); err != nil {
		log.Error("could not publish the ledger root", "error", err)
	}
}

// appSyncInterval is how often the apps' monitors are brought in line
// with the platform's app list: each app's zero-config check follows its
// address, and a deleted app's monitor goes.
const appSyncInterval = 5 * time.Minute

// startAppSync runs the app sync against the control plane the platform
// clock is configured with, as this attested app. Off the platform, or on
// an instance without the platform clock, there is no control plane to
// ask and the apps' monitors keep what they have.
func startAppSync(ctx context.Context, log *slog.Logger, host *tenancy.Host, platformAPI *clock.Platform) {
	if platformAPI == nil {
		log.Info("the apps' monitors are not synced with the platform: no control plane is configured")
		return
	}
	source := func(ctx context.Context) ([]tenancy.App, bool, error) {
		apps, complete, err := platformAPI.Apps(ctx)
		if err != nil {
			return nil, false, err
		}
		out := make([]tenancy.App, 0, len(apps))
		for _, a := range apps {
			out = append(out, tenancy.App{
				ID: a.ID, Name: a.Name, DisplayName: a.DisplayName,
				AppType: a.AppType, Hostname: a.Hostname, Deployed: a.Deployed,
			})
		}
		return out, complete, nil
	}
	go host.RunSync(ctx, source, appSyncInterval)
}

// walletNotices puts pages and notices in front of people through the
// platform, as this attested app.
type walletNotices struct{ platform *clock.Platform }

func (w walletNotices) Form(ctx context.Context, sub, form string) (string, error) {
	return w.platform.Notify(ctx, sub, "app-form", map[string]string{"kind": "request", "form": form})
}

// Message sends a notice. The wallet writes its own words for a notice, so
// the title and body are for the channels that can carry them.
func (w walletNotices) Message(ctx context.Context, sub, _, _ string) (string, error) {
	return w.platform.Notify(ctx, sub, "app-message", map[string]string{"kind": "response", "path": "/"})
}

// wireOnCall gives an app's monitor its paging.
func wireOnCall(t *tenancy.Tenant, log *slog.Logger, host **tenancy.Host, platformAPI *clock.Platform,
	mon *core.Monitor, send oncall.Mailer) {
	store, err := oncall.OpenStore(t.Dir())
	if err != nil {
		log.Error("could not open an app's on-call data", "app", t.ID, "error", err)
		return
	}
	id := t.ID
	d := &oncall.Dispatcher{
		Store: store, AppID: id, Mail: send, Log: log.With("app", id),
		Callback:   "/api/v1/apps/" + id + "/oncall/answer",
		ConsoleURL: consoleURL(mon, id),
		AppName: func() string {
			if *host == nil {
				return ""
			}
			a, _ := (*host).KnownApp(id)
			if a.DisplayName != "" {
				return a.DisplayName
			}
			return a.Name
		},
		Team: func(ctx context.Context) ([]oncall.Member, error) {
			if platformAPI == nil {
				return nil, errors.New("no control plane is configured")
			}
			team, err := platformAPI.Team(ctx, id)
			if err != nil {
				return nil, err
			}
			out := make([]oncall.Member, 0, len(team))
			for _, m := range team {
				out = append(out, oncall.Member{Sub: m.Sub, Name: m.Name, Role: m.Role})
			}
			return out, nil
		},
	}
	if platformAPI != nil {
		d.Wallet = walletNotices{platform: platformAPI}
	}
	d.Prepare()
	t.OnCall = d
}

// consoleURL is the app's Status tab in the portal of this environment.
func consoleURL(mon *core.Monitor, appID string) string {
	pc := mon.PlatformClockConfig()
	if pc == nil {
		return ""
	}
	portal := "https://developer.privasys.org"
	if strings.Contains(pc.ManagementURL, "test") {
		portal = "https://developer.test.privasys.org"
	}
	return portal + "/dashboard/apps/" + appID + "/?tab=status"
}

// publishClockKey commits the platform clock's key to the leaf
// certificate, on an instance running the platform clock only. The
// platform reads it there before handing the key to the runtimes.
func publishClockKey(ctx context.Context, log *slog.Logger, manager *platform.Manager, svc *clock.Service) {
	if manager == nil || !svc.Enabled() {
		return
	}
	if err := manager.PublishClockKey(ctx, svc.Signer().PublicKey()); err != nil {
		log.Error("could not publish the clock key", "error", err)
	}
}

// recordBoot writes the boot down, with the gap since the last one.
//
// This is the honesty the coverage figure rests on. A monitor that was
// not running did not observe a service that was up, and a gap in the
// readings is otherwise indistinguishable from a quiet period.
func recordBoot(log *slog.Logger, mon *core.Monitor) {
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
	if cfg.Pack != "" {
		if raw, err := os.ReadFile(cfg.Pack); err == nil {
			if _, err := pack.Parse(raw); err != nil {
				return err
			}
			req.Pack = raw
		} else {
			req.PackRef = cfg.Pack
		}
	}
	_, err := mon.Configure(auth.System("dev"), req, cfg.PackDir)
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
