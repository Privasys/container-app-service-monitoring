// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Readings, and the intervals they are folded into.
//
// A tick of the scheduler produces every reading that was due in that
// second, and they are written as one transaction: one ledger commit,
// one link on the lineage chain, one root that covers the lot. At two
// hundred monitors on a thirty second interval that is about seven
// readings a commit and one commit a second, comfortably inside what
// the ledger sustains, and it keeps the record's version count
// proportional to time rather than to how many things are watched.

// Bucket widths.
const (
	WidthMinute = int64(60)
	WidthHour   = int64(3600)
)

// RecordSamples writes a tick's readings and runs detection over them.
//
// Detection happens inside the same transaction, so an alert names the
// root and version at which the change it reports was recorded. A
// consumer can therefore take the alert to the monitor, ask for that
// version, and be handed the readings that caused it.
func (m *Monitor) RecordSamples(samples []model.Sample) (*model.Transaction, []Alert, error) {
	if len(samples) == 0 {
		return nil, nil, nil
	}
	now := m.Now()
	var tr *model.Transaction
	var alerts []Alert

	err := m.st.Do(func(tx *store.Tx) error {
		ops := make([]model.WriteOp, 0, len(samples)*2)
		ids := make([]string, 0, len(samples))
		for i := range samples {
			s := &samples[i]
			if s.ID == "" {
				id, err := NewID("smp")
				if err != nil {
					return err
				}
				s.ID = id
			}
			op, err := sampleOp(*s)
			if err != nil {
				return err
			}
			ops = append(ops, op)
			ids = append(ids, s.ID)
		}

		detected, detectOps, err := m.detect(tx, samples, now)
		if err != nil {
			return err
		}
		ops = append(ops, detectOps...)

		message := fmt.Sprintf("Record %d readings", len(samples))
		if len(samples) == 1 {
			message = fmt.Sprintf("Record a reading of %s", summarise(monitorName(tx, samples[0].MonitorID), 40))
		}
		serviceID := samples[0].ServiceID
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindSamples, Service: serviceID, ObjectIDs: ids,
			Author: model.SystemAuthor(), Timestamp: now, Message: message,
		}, ops)
		if err != nil {
			return err
		}
		// The alerts carry the state the transaction produced, which is
		// only known once it has committed.
		for i := range detected {
			detected[i].LedgerRoot, detected[i].LedgerVersion = tx.Root()
		}
		alerts = detected
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	for _, a := range alerts {
		if m.hooks.OnAlert != nil {
			m.hooks.OnAlert(a)
		}
	}
	return tr, alerts, nil
}

func sampleOp(s model.Sample) (model.WriteOp, error) {
	steps, err := jsonBytes(s.Steps)
	if err != nil {
		return model.WriteOp{}, err
	}
	return model.WriteOp{
		Table: "samples", Key: map[string]any{"id": s.ID},
		Values: map[string]any{
			"monitor_id": s.MonitorID, "monitor_version": s.MonitorVersion,
			"component_id": s.ComponentID, "service_id": s.ServiceID,
			"vantage": s.Vantage, "started_at": s.StartedAt, "duration_ms": s.DurationMs,
			"verdict": s.Verdict, "failed_step": s.FailedStep, "error_class": s.ErrorClass,
			"detail": clip(s.Detail, 1024), "steps": steps,
			"manual": s.Manual, "in_maintenance": s.InMaintenance, "pruned": false,
		},
	}, nil
}

func monitorName(tx *store.Tx, id string) string {
	row, err := tx.QueryOne("SELECT name FROM `monitors` WHERE id = " + store.Lit(id))
	if err != nil || row == nil {
		return id
	}
	return row.Str("name")
}

// Fold turns readings into intervals.
//
// It only ever folds intervals that are closed, so a bucket is written
// once and never revised: a folded reading that could still change is
// not evidence. Minute buckets are folded from readings, hour buckets
// from minute buckets, and both are ledger rows in their own right, so
// a report can bundle them with inclusion proofs.
func (m *Monitor) Fold(before int64) (*model.Transaction, error) {
	minuteEnd := (before / WidthMinute) * WidthMinute
	hourEnd := (before / WidthHour) * WidthHour

	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		ops, folded, err := m.foldMinutes(tx, minuteEnd)
		if err != nil {
			return err
		}
		hourOps, hourFolded, err := m.foldHours(tx, hourEnd)
		if err != nil {
			return err
		}
		ops = append(ops, hourOps...)
		if len(ops) == 0 {
			return nil
		}
		message := fmt.Sprintf("Fold %d minutes and %d hours of readings", folded, hourFolded)
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindRollup, Author: model.SystemAuthor(),
			Timestamp: m.Now(), Message: message,
		}, ops)
		return err
	})
	return tr, err
}

// foldMinutes folds every closed minute that has readings and no bucket.
func (m *Monitor) foldMinutes(tx *store.Tx, before int64) ([]model.WriteOp, int, error) {
	watermark, err := m.watermark(tx, "fold.minute")
	if err != nil {
		return nil, 0, err
	}
	if watermark == 0 {
		first, err := tx.QueryOne("SELECT MIN(started_at) AS first FROM `samples`")
		if err != nil {
			return nil, 0, err
		}
		if first == nil || !first.Has("first") {
			return nil, 0, nil
		}
		watermark = (first.Int("first") / WidthMinute) * WidthMinute
	}
	if watermark >= before {
		return nil, 0, nil
	}

	rows, err := tx.Query("SELECT * FROM `samples` WHERE started_at >= " + store.Lit(watermark) +
		" AND started_at < " + store.Lit(before) + " AND manual = FALSE ORDER BY started_at")
	if err != nil {
		return nil, 0, err
	}

	folds := map[foldKey]*fold{}
	for _, row := range rows {
		k := foldKey{monitor: row.Str("monitor_id"), start: (row.Int("started_at") / WidthMinute) * WidthMinute}
		f := folds[k]
		if f == nil {
			f = &fold{
				monitorID: k.monitor, componentID: row.Str("component_id"),
				serviceID: row.Str("service_id"), start: k.start, width: WidthMinute,
			}
			folds[k] = f
		}
		f.addSample(row.Str("verdict"), int(row.Int("duration_ms")), row.Bool("in_maintenance"))
	}

	ops := make([]model.WriteOp, 0, len(folds)+1)
	for _, f := range sortedFolds(folds) {
		ops = append(ops, f.op())
	}
	ops = append(ops, watermarkOp("fold.minute", before))
	return ops, len(folds), nil
}

// foldHours folds closed hours from the minute buckets.
func (m *Monitor) foldHours(tx *store.Tx, before int64) ([]model.WriteOp, int, error) {
	watermark, err := m.watermark(tx, "fold.hour")
	if err != nil {
		return nil, 0, err
	}
	if watermark == 0 {
		first, err := tx.QueryOne("SELECT MIN(bucket_start) AS first FROM `buckets` WHERE width_seconds = " +
			store.Lit(WidthMinute))
		if err != nil {
			return nil, 0, err
		}
		if first == nil || !first.Has("first") {
			return nil, 0, nil
		}
		watermark = (first.Int("first") / WidthHour) * WidthHour
	}
	if watermark >= before {
		return nil, 0, nil
	}

	rows, err := tx.Query("SELECT * FROM `buckets` WHERE width_seconds = " + store.Lit(WidthMinute) +
		" AND bucket_start >= " + store.Lit(watermark) + " AND bucket_start < " + store.Lit(before) +
		" ORDER BY bucket_start")
	if err != nil {
		return nil, 0, err
	}

	folds := map[foldKey]*fold{}
	for _, row := range rows {
		k := foldKey{monitor: row.Str("monitor_id"), start: (row.Int("bucket_start") / WidthHour) * WidthHour}
		f := folds[k]
		if f == nil {
			f = &fold{
				monitorID: k.monitor, componentID: row.Str("component_id"),
				serviceID: row.Str("service_id"), start: k.start, width: WidthHour,
			}
			folds[k] = f
		}
		f.addBucket(bucketFromRow(row))
	}

	ops := make([]model.WriteOp, 0, len(folds)+1)
	for _, f := range sortedFolds(folds) {
		ops = append(ops, f.op())
	}
	ops = append(ops, watermarkOp("fold.hour", before))
	return ops, len(folds), nil
}

// fold accumulates one interval.
type fold struct {
	monitorID, componentID, serviceID string
	start, width                      int64
	up, degraded, down, errors, maint int
	latencies                         []int
	// downIntervals counts finer intervals that were themselves down,
	// which is what decides an hour's verdict.
	downIntervals int
	seenIntervals int
}

func (f *fold) addSample(verdict string, durationMs int, inMaintenance bool) {
	switch verdict {
	case model.VerdictUp:
		f.up++
	case model.VerdictDegraded:
		f.degraded++
	case model.VerdictDown:
		f.down++
	default:
		f.errors++
	}
	if inMaintenance {
		f.maint++
	}
	if verdict != model.VerdictError {
		f.latencies = append(f.latencies, durationMs)
	}
}

func (f *fold) addBucket(b model.Bucket) {
	f.up += b.Up
	f.degraded += b.Degraded
	f.down += b.Down
	f.errors += b.Errors
	f.maint += b.InMaintenance
	f.seenIntervals++
	if b.Verdict == model.VerdictDown {
		f.downIntervals++
	}
	if b.LatencyP95 > 0 {
		f.latencies = append(f.latencies, b.LatencyP95)
	}
	if b.LatencyMax > f.latencyMax() {
		f.latencies = append(f.latencies, b.LatencyMax)
	}
}

func (f *fold) latencyMax() int {
	max := 0
	for _, l := range f.latencies {
		if l > max {
			max = l
		}
	}
	return max
}

// verdict decides what the interval says.
//
// At minute resolution the rule is that the interval is down when at
// least half of its readings failed. A single failure in a minute with
// one reading is therefore downtime, and one failure out of four
// readings is degraded rather than down: a request that succeeded on
// the retry is not the same fact as a service that was not there. An
// hour is down if any minute inside it was, which is deliberately
// pessimistic, and is why a report loads the minutes of any hour that
// was not uniformly up rather than resting on the hour.
func (f *fold) verdict() string {
	if f.width >= WidthHour && f.seenIntervals > 0 {
		if f.downIntervals > 0 {
			return model.VerdictDown
		}
		if f.degraded > 0 {
			return model.VerdictDegraded
		}
		if f.up > 0 {
			return model.VerdictUp
		}
		return model.VerdictError
	}
	readings := f.up + f.degraded + f.down
	if readings == 0 {
		return model.VerdictError
	}
	if f.down*2 >= readings {
		return model.VerdictDown
	}
	if f.down > 0 || f.degraded > 0 {
		return model.VerdictDegraded
	}
	return model.VerdictUp
}

func (f *fold) op() model.WriteOp {
	p50, p95, max := percentiles(f.latencies)
	return model.WriteOp{
		Table: "buckets",
		Key: map[string]any{
			"monitor_id": f.monitorID, "width_seconds": f.width, "bucket_start": f.start,
		},
		Values: map[string]any{
			"component_id": f.componentID, "service_id": f.serviceID,
			"up_count": f.up, "degraded_count": f.degraded, "down_count": f.down,
			"error_count": f.errors, "maint_count": f.maint,
			"latency_p50": p50, "latency_p95": p95, "latency_max": max,
			"verdict": f.verdict(),
		},
	}
}

// foldKey identifies one interval of one monitor.
type foldKey struct {
	monitor string
	start   int64
}

func sortedFolds(in map[foldKey]*fold) []*fold {
	out := make([]*fold, 0, len(in))
	for _, f := range in {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].start != out[j].start {
			return out[i].start < out[j].start
		}
		return out[i].monitorID < out[j].monitorID
	})
	return out
}

func percentiles(values []int) (p50, p95, max int) {
	if len(values) == 0 {
		return 0, 0, 0
	}
	sorted := append([]int(nil), values...)
	sort.Ints(sorted)
	pick := func(q float64) int {
		idx := int(q * float64(len(sorted)-1))
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sorted) {
			idx = len(sorted) - 1
		}
		return sorted[idx]
	}
	return pick(0.5), pick(0.95), sorted[len(sorted)-1]
}

func bucketFromRow(row store.Row) model.Bucket {
	return model.Bucket{
		MonitorID: row.Str("monitor_id"), ComponentID: row.Str("component_id"),
		ServiceID: row.Str("service_id"),
		Start:     row.Int("bucket_start"), Width: row.Int("width_seconds"),
		Up: int(row.Int("up_count")), Degraded: int(row.Int("degraded_count")),
		Down: int(row.Int("down_count")), Errors: int(row.Int("error_count")),
		InMaintenance: int(row.Int("maint_count")),
		LatencyP50:    int(row.Int("latency_p50")), LatencyP95: int(row.Int("latency_p95")),
		LatencyMax: int(row.Int("latency_max")), Verdict: row.Str("verdict"),
	}
}

// -- the small registry of watermarks --------------------------------------

func (m *Monitor) watermark(tx *store.Tx, name string) (int64, error) {
	row, err := tx.QueryOne("SELECT v FROM `registry` WHERE k = " + store.Lit("watermark."+name))
	if err != nil || row == nil {
		return 0, err
	}
	var v int64
	if err := json.Unmarshal(row.Bytes("v"), &v); err != nil {
		return 0, nil
	}
	return v, nil
}

func watermarkOp(name string, value int64) model.WriteOp {
	raw, _ := json.Marshal(value)
	return model.WriteOp{
		Table: "registry", Key: map[string]any{"k": "watermark." + name},
		Values: map[string]any{"v": model.Binary(raw), "updated_at": value},
	}
}

// registryPut stores a small instance-level document.
func registryPut(name string, v any) (model.WriteOp, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return model.WriteOp{}, err
	}
	return model.WriteOp{
		Table: "registry", Key: map[string]any{"k": name},
		Values: map[string]any{"v": model.Binary(raw), "updated_at": int64(0)},
	}, nil
}

func registryGet(tx *store.Tx, name string, into any) (bool, error) {
	row, err := tx.QueryOne("SELECT v FROM `registry` WHERE k = " + store.Lit(name))
	if err != nil || row == nil {
		return false, err
	}
	raw := row.Bytes("v")
	if len(raw) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return false, fmt.Errorf("core: registry %s: %w", name, err)
	}
	return true, nil
}

// refreshEgress rebuilds the outbound allowlist from the monitors and
// the declared callbacks. It runs after every change to either, so the
// set of hosts this instance may contact is always exactly the set
// somebody signed a transaction to declare.
func (m *Monitor) refreshEgress() {
	if m.egress == nil || m.egress.IsOpen() {
		return
	}
	entries := map[string]bool{}
	for _, h := range m.Config().CallbackHosts {
		entries[strings.ToLower(h)] = true
	}
	_ = m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT steps FROM `monitors` WHERE enabled = TRUE")
		if err != nil {
			return err
		}
		for _, row := range rows {
			var steps []model.Step
			if raw := row.Bytes("steps"); len(raw) > 0 {
				if err := json.Unmarshal(raw, &steps); err != nil {
					continue
				}
			}
			for _, s := range steps {
				if host := hostOfTemplate(s.URL); host != "" {
					entries[host] = true
				}
			}
		}
		rows, err = tx.Query("SELECT callback_url FROM `services`")
		if err != nil {
			return err
		}
		for _, row := range rows {
			if host := hostOfTemplate(row.Str("callback_url")); host != "" {
				entries[host] = true
			}
		}
		return nil
	})
	list := make([]string, 0, len(entries))
	for h := range entries {
		list = append(list, h)
	}
	sort.Strings(list)
	m.egress.Replace(list)
}

// hostOfTemplate extracts the host from a possibly templated URL. A URL
// whose host is itself a placeholder cannot be allowlisted, and is
// refused at request time rather than silently permitted.
func hostOfTemplate(raw string) string {
	if raw == "" {
		return ""
	}
	rest := raw
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if strings.Contains(rest, "{{") {
		return ""
	}
	if i := strings.LastIndex(rest, ":"); i > 0 {
		rest = rest[:i]
	}
	return strings.ToLower(rest)
}
