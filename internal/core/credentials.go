// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

package core

import (
	"fmt"
	"strings"

	"github.com/Privasys/container-app-service-monitoring/internal/auth"
	"github.com/Privasys/container-app-service-monitoring/internal/model"
	"github.com/Privasys/container-app-service-monitoring/internal/secrets"
	"github.com/Privasys/container-app-service-monitoring/internal/store"
)

// Credentials: the record of them, which is public to anyone who may
// read the log, and the values, which are not in the record at all.
//
// What is written down is the name, the hosts the credential is bound
// to, a keyed fingerprint, and the moments it was created, rotated,
// used and destroyed. That is enough to audit how a monitor was
// authorised without the audit itself becoming a way to read the
// credential.

// PutSecret stores or rotates a credential.
func (m *Monitor) PutSecret(p *auth.Principal, name, value string, hosts []string, description, message string) (*model.SecretMeta, *model.Transaction, error) {
	if !p.Can(auth.PermSecrets) {
		return nil, nil, fmt.Errorf("%s may not manage credentials", p.Acting)
	}
	if err := secrets.ValidName(name); err != nil {
		return nil, nil, err
	}
	clean, err := secrets.NormaliseHosts(hosts)
	if err != nil {
		return nil, nil, err
	}
	if len(clean) == 0 {
		return nil, nil, fmt.Errorf("a credential must be bound to at least one host; " +
			"that binding is what stops it being sent anywhere else")
	}

	fingerprint, err := m.vault.Put(name, value, clean)
	if err != nil {
		return nil, nil, err
	}

	now := m.Now()
	meta := &model.SecretMeta{
		Name: name, Hosts: clean, Description: description,
		Fingerprint: fingerprint, CreatedAt: now,
	}
	var tr *model.Transaction
	err = m.st.Do(func(tx *store.Tx) error {
		existing, err := readSecretMeta(tx, name)
		if err != nil {
			return err
		}
		values := map[string]any{
			"hosts": clip(strings.Join(clean, ","), 1024), "description": clip(description, 512),
			"fingerprint": fingerprint, "destroyed_at": int64(0),
		}
		if existing == nil {
			values["created_at"] = now
			values["rotated_at"] = int64(0)
			values["used_at"] = int64(0)
		} else {
			meta.CreatedAt = existing.CreatedAt
			meta.RotatedAt = now
			values["rotated_at"] = now
		}
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindSecretPut, ObjectIDs: []string{name},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{{
			Table: "secrets_meta", Key: map[string]any{"name": name}, Values: values,
		}})
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	return meta, tr, nil
}

// DestroySecret destroys a credential's key. The value is unrecoverable
// from that moment; everything the record says about it stays.
func (m *Monitor) DestroySecret(p *auth.Principal, name, message string) (*model.Transaction, error) {
	if !p.Can(auth.PermSecrets) {
		return nil, fmt.Errorf("%s may not manage credentials", p.Acting)
	}
	if !m.vault.Has(name) {
		return nil, fmt.Errorf("no credential named %s", name)
	}
	if err := m.vault.Destroy(name); err != nil {
		return nil, err
	}
	now := m.Now()
	var tr *model.Transaction
	err := m.st.Do(func(tx *store.Tx) error {
		var err error
		tr, err = m.commit(tx, model.Envelope{
			Kind: model.KindSecretDestroy, ObjectIDs: []string{name},
			Author: p.Author(), Timestamp: now, Message: message,
		}, []model.WriteOp{{
			Table: "secrets_meta", Key: map[string]any{"name": name},
			Values: map[string]any{"destroyed_at": now},
		}})
		return err
	})
	return tr, err
}

// Secrets lists what the monitor holds, never what it holds it as.
func (m *Monitor) Secrets() ([]model.SecretMeta, error) {
	var out []model.SecretMeta
	err := m.st.Do(func(tx *store.Tx) error {
		rows, err := tx.Query("SELECT * FROM `secrets_meta` ORDER BY name")
		if err != nil {
			return err
		}
		for _, row := range rows {
			meta := secretFromRow(row)
			// The vault is the authority on whether a value is still
			// usable. A row saying otherwise would be a record that has
			// drifted from the thing it describes.
			if _, ok := m.vault.Bindings(meta.Name); !ok && meta.DestroyedAt == 0 {
				meta.DestroyedAt = -1
			}
			out = append(out, *meta)
		}
		return nil
	})
	return out, err
}

func readSecretMeta(tx *store.Tx, name string) (*model.SecretMeta, error) {
	row, err := tx.QueryOne("SELECT * FROM `secrets_meta` WHERE name = " + store.Lit(name))
	if err != nil || row == nil {
		return nil, err
	}
	return secretFromRow(row), nil
}

func secretFromRow(row store.Row) *model.SecretMeta {
	return &model.SecretMeta{
		Name: row.Str("name"), Hosts: splitCSV(row.Str("hosts")),
		Description: row.Str("description"), Fingerprint: row.Str("fingerprint"),
		CreatedAt: row.Int("created_at"), RotatedAt: row.Int("rotated_at"),
		DestroyedAt: row.Int("destroyed_at"), UsedAt: row.Int("used_at"),
	}
}
