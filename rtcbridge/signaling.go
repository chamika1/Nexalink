package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

type credentials struct {
	Room      string `json:"room"`
	Initiator string `json:"initiator_token"`
	Responder string `json:"responder_token"`
}

type signaling struct {
	base   string
	client *http.Client
}

func newSignaling(raw string) (signaling, error) {
	address, err := url.Parse(raw)
	if err != nil || address.Scheme != "https" || address.Host == "" ||
		address.User != nil || address.RawQuery != "" || address.Fragment != "" {
		return signaling{}, errors.New("a trusted HTTPS signaling URL is required")
	}
	return signaling{strings.TrimRight(raw, "/"), &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}}, nil
}

func validToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(token) == 32
}

func (s signaling) exchange(ctx context.Context, method, path, token string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	reply, err := s.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("could not contact signaling service")
	}
	defer reply.Body.Close()
	if reply.StatusCode < 200 || reply.StatusCode >= 300 {
		return nil, reply.StatusCode, fmt.Errorf("signaling service returned HTTP %d", reply.StatusCode)
	}
	const limit = 64 << 10
	payload, err := io.ReadAll(io.LimitReader(reply.Body, limit+1))
	if err != nil || len(payload) > limit {
		return nil, 0, errors.New("invalid signaling response length")
	}
	return payload, reply.StatusCode, nil
}

func (s signaling) create(ctx context.Context) (credentials, error) {
	raw, status, err := s.exchange(ctx, http.MethodPost, "/rooms", "", nil)
	if err != nil {
		return credentials{}, err
	}
	var keys credentials
	if status != http.StatusCreated || json.Unmarshal(raw, &keys) != nil ||
		!validToken(keys.Room) || !validToken(keys.Initiator) || !validToken(keys.Responder) {
		return credentials{}, errors.New("invalid room credentials")
	}
	return keys, nil
}

func (s signaling) publish(ctx context.Context, path, token string, description *webrtc.SessionDescription) error {
	payload, err := json.Marshal(description)
	if err != nil {
		return err
	}
	_, status, err := s.exchange(ctx, http.MethodPut, path, token, payload)
	if err == nil && status != http.StatusNoContent {
		return errors.New("unexpected signaling publish response")
	}
	return err
}

func (s signaling) wait(ctx context.Context, path, token string, kind webrtc.SDPType) (webrtc.SessionDescription, error) {
	poll := time.NewTicker(time.Second)
	defer poll.Stop()
	for {
		payload, status, err := s.exchange(ctx, http.MethodGet, path, token, nil)
		if err != nil {
			return webrtc.SessionDescription{}, err
		}
		if status == http.StatusOK {
			var description webrtc.SessionDescription
			if json.Unmarshal(payload, &description) != nil || description.Type != kind || description.SDP == "" {
				return description, errors.New("invalid remote connection description")
			}
			return description, nil
		}
		if status != http.StatusNoContent {
			return webrtc.SessionDescription{}, errors.New("unexpected signaling poll response")
		}
		select {
		case <-poll.C:
		case <-ctx.Done():
			return webrtc.SessionDescription{}, ctx.Err()
		}
	}
}
