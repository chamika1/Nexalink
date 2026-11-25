package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	roomLifetime   = 5 * time.Minute
	maxRooms       = 256
	maxDescription = 64 << 10
)

type credentials struct {
	Room      string `json:"room"`
	Initiator string `json:"initiator_token"`
	Responder string `json:"responder_token"`
}

type room struct {
	credentials
	expires time.Time
	offer   []byte
	answer  []byte
}

type rendezvous struct {
	mu    sync.Mutex
	rooms map[string]*room
	now   func() time.Time
}

func token() string {
	var bytes [32]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:])
}

func (s *rendezvous) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /rooms", s.create)
	mux.HandleFunc("PUT /rooms/{id}/{side}", s.exchange)
	mux.HandleFunc("GET /rooms/{id}/{side}", s.exchange)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		mux.ServeHTTP(w, r)
	})
}

func (s *rendezvous) create(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	now := s.now()
	for id, entry := range s.rooms {
		if !now.Before(entry.expires) {
			delete(s.rooms, id)
		}
	}
	if len(s.rooms) >= maxRooms {
		s.mu.Unlock()
		http.Error(w, "room capacity reached", http.StatusServiceUnavailable)
		return
	}
	keys := credentials{Room: token(), Initiator: token(), Responder: token()}
	entry := &room{credentials: keys, expires: now.Add(roomLifetime)}
	s.rooms[keys.Room] = entry
	s.mu.Unlock()
	time.AfterFunc(roomLifetime, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.rooms[keys.Room] == entry {
			delete(s.rooms, keys.Room)
		}
	})

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(keys)
}

func (s *rendezvous) exchange(w http.ResponseWriter, r *http.Request) {
	id, side := r.PathValue("id"), r.PathValue("side")
	if side != "offer" && side != "answer" {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	entry := s.rooms[id]
	if entry == nil || !s.now().Before(entry.expires) {
		delete(s.rooms, id)
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	put := r.Method == http.MethodPut
	sender, receiver := entry.Initiator, entry.Responder
	field := &entry.offer
	if side == "answer" {
		sender, receiver = entry.Responder, entry.Initiator
		field = &entry.answer
	}
	expected := receiver
	if put {
		expected = sender
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+expected)) != 1 {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}

	if !put {
		payload := *field
		s.mu.Unlock()
		if len(payload) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(payload)
		return
	}
	s.mu.Unlock()
	payload, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxDescription))
	if err != nil {
		var limit *http.MaxBytesError
		if errors.As(err, &limit) {
			http.Error(w, "description too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read description", http.StatusBadRequest)
		return
	}
	if len(payload) == 0 {
		http.Error(w, "description required", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	if s.rooms[id] != entry || !s.now().Before(entry.expires) {
		s.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if len(*field) != 0 || (side == "answer" && len(entry.offer) == 0) {
		s.mu.Unlock()
		http.Error(w, "unexpected description", http.StatusConflict)
		return
	}
	*field = payload
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	address := flag.String("listen", "127.0.0.1:8080", "listen address")
	cert := flag.String("tls-cert", "", "TLS certificate file")
	key := flag.String("tls-key", "", "TLS private key file")
	flag.Parse()
	state := &rendezvous{rooms: make(map[string]*room), now: time.Now}
	server := &http.Server{
		Addr: *address, Handler: state.routes(), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8192,
	}
	if *cert != "" || *key != "" {
		log.Fatal(server.ListenAndServeTLS(*cert, *key))
	}
	host, _, err := net.SplitHostPort(*address)
	if err != nil || (host != "localhost" && !net.ParseIP(host).IsLoopback()) {
		log.Fatal("TLS is required for a non-loopback listener")
	}
	log.Fatal(server.ListenAndServe())
}
