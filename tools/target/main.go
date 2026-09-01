// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Command target is a small stand-in for a customer's service.
//
// It exists so the reference service model has something real to
// exercise and so the end-to-end suite can make a service fail on
// demand. It is deliberately a service with a login and a resource
// lifecycle rather than a page that returns 200, because that is the
// difference the product is about: a monitor that only proves the
// homepage answers proves very little.
//
//	POST /login          {"user","password"} -> {"token"}
//	POST /orders         Authorization: Bearer <token> -> {"id","status"}
//	GET  /orders/{id}    Authorization: Bearer <token> -> {"id","status"}
//	DELETE /orders/{id}  Authorization: Bearer <token> -> 204
//	POST /admin/break    {"seconds"} makes /orders fail, to test detection
//	POST /admin/heal     stops it failing
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type server struct {
	mu       sync.Mutex
	orders   map[string]string
	brokenTo time.Time
	slowTo   time.Time
	user     string
	password string
	token    string
	next     int
	hooks    []delivery
}

func main() {
	port := os.Getenv("TARGET_PORT")
	if port == "" {
		port = "18081"
	}
	s := &server{
		orders:   map[string]string{},
		user:     envOr("TARGET_USER", "monitor"),
		password: envOr("TARGET_PASSWORD", "correct horse battery staple"),
		token:    "session-" + envOr("TARGET_TOKEN", "0a1b2c3d4e5f"),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /orders", s.createOrder)
	mux.HandleFunc("GET /orders/{id}", s.getOrder)
	mux.HandleFunc("DELETE /orders/{id}", s.deleteOrder)
	mux.HandleFunc("POST /hooks", s.hook)
	mux.HandleFunc("GET /hooks/received", s.received)
	mux.HandleFunc("POST /admin/break", s.breakIt)
	mux.HandleFunc("POST /admin/heal", s.heal)
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok"})
	})

	log.Printf("target listening on :%s", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		User     string `json:"user"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad request"})
		return
	}
	if body.User != s.user || body.Password != s.password {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	writeJSON(w, 200, map[string]any{"token": s.token, "user": body.User})
}

func (s *server) authed(r *http.Request) bool {
	return r.Header.Get("Authorization") == "Bearer "+s.token
}

func (s *server) createOrder(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	if s.faulty(w) {
		return
	}
	var body struct {
		Reference string `json:"reference"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	s.mu.Lock()
	s.next++
	id := fmt.Sprintf("ord-%04d", s.next)
	s.orders[id] = "accepted"
	s.mu.Unlock()

	writeJSON(w, 201, map[string]any{"id": id, "status": "accepted", "reference": body.Reference})
}

func (s *server) getOrder(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	if s.faulty(w) {
		return
	}
	s.mu.Lock()
	status, ok := s.orders[r.PathValue("id")]
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]any{"error": "no such order"})
		return
	}
	writeJSON(w, 200, map[string]any{"id": r.PathValue("id"), "status": status})
}

func (s *server) deleteOrder(w http.ResponseWriter, r *http.Request) {
	if !s.authed(r) {
		writeJSON(w, 401, map[string]any{"error": "not authenticated"})
		return
	}
	s.mu.Lock()
	delete(s.orders, r.PathValue("id"))
	s.mu.Unlock()
	w.WriteHeader(204)
}

// faulty is how the suite makes the service fail on demand, so
// detection, incidents and alerting can be exercised end to end rather
// than asserted about.
func (s *server) faulty(w http.ResponseWriter) bool {
	s.mu.Lock()
	broken := time.Now().Before(s.brokenTo)
	slow := time.Now().Before(s.slowTo)
	s.mu.Unlock()
	if slow {
		time.Sleep(1200 * time.Millisecond)
	}
	if broken {
		writeJSON(w, 503, map[string]any{"error": "the order service is unavailable"})
		return true
	}
	return false
}

func (s *server) breakIt(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Seconds int  `json:"seconds"`
		Slow    bool `json:"slow"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Seconds <= 0 {
		body.Seconds = 60
	}
	s.mu.Lock()
	if body.Slow {
		s.slowTo = time.Now().Add(time.Duration(body.Seconds) * time.Second)
	} else {
		s.brokenTo = time.Now().Add(time.Duration(body.Seconds) * time.Second)
	}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"broken_for": body.Seconds, "slow": body.Slow})
}

func (s *server) heal(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.brokenTo = time.Time{}
	s.slowTo = time.Time{}
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"healed": true})
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// The callback receiver. It exists so the end-to-end suite can prove
// the whole notification path rather than assert about it: an alert is
// signed, delivered, and verifiable by whoever receives it with nothing
// but the key the monitor publishes.
func (s *server) hook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, 400, map[string]any{"error": "unreadable"})
		return
	}
	headers := map[string]string{}
	for k, v := range r.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}
	s.mu.Lock()
	s.hooks = append(s.hooks, delivery{Headers: headers, Body: string(body)})
	s.mu.Unlock()
	w.WriteHeader(204)
}

func (s *server) received(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	out := append([]delivery(nil), s.hooks...)
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"deliveries": out})
}

// delivery is one notification as it arrived, kept verbatim: the
// signature covers the exact bytes, so re-serialising them would make
// the check meaningless.
type delivery struct {
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
