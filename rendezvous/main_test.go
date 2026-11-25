package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPrivateOfferAndAnswer(t *testing.T) {
	now := time.Unix(0, 0)
	handler := (&rendezvous{rooms: make(map[string]*room), now: func() time.Time { return now }}).routes()
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		out := httptest.NewRecorder()
		handler.ServeHTTP(out, req)
		return out
	}
	created := request("POST", "/rooms", "", "")
	var keys credentials
	if created.Code != http.StatusCreated || json.Unmarshal(created.Body.Bytes(), &keys) != nil ||
		keys.Room == "" || keys.Initiator == keys.Responder {
		t.Fatal("room credentials missing")
	}
	offer, answer := "/rooms/"+keys.Room+"/offer", "/rooms/"+keys.Room+"/answer"
	expect := func(method, path, token, body string, status int, result string) {
		t.Helper()
		out := request(method, path, token, body)
		if out.Code != status || (result != "" && out.Body.String() != result) {
			t.Fatalf("%s: got status %d and body %q", method, out.Code, out.Body.String())
		}
	}
	expect("GET", offer, keys.Initiator, "", 404, "")
	expect("GET", offer, keys.Responder, "", 204, "")
	expect("PUT", offer, keys.Responder, "wrong role", 404, "")
	expect("PUT", answer, keys.Responder, "too early", 409, "")
	expect("PUT", offer, keys.Initiator, strings.Repeat("x", maxDescription+1), 413, "")
	expect("PUT", offer, keys.Initiator, "offer data", 204, "")
	expect("GET", offer, keys.Responder, "", 200, "offer data")
	expect("PUT", offer, keys.Initiator, "overwrite", 409, "")
	expect("PUT", answer, keys.Responder, "answer data", 204, "")
	expect("GET", answer, keys.Initiator, "", 200, "answer data")
	now = now.Add(roomLifetime)
	expect("GET", answer, keys.Initiator, "", 404, "")
}
