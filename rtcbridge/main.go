package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"time"

	"github.com/pion/webrtc/v4"
)

const channelLabel = "nexalink-stream-v1"
const chunkSize = 16 * 1024

func negotiate(ctx context.Context, connection *webrtc.PeerConnection, server signaling, keys credentials, create bool) error {
	path := "/rooms/" + keys.Room
	token := keys.Responder
	localPath := path + "/answer"
	var local webrtc.SessionDescription
	var err error
	if create {
		token = keys.Initiator
		localPath = path + "/offer"
		local, err = connection.CreateOffer(nil)
	} else {
		offer, err := server.wait(ctx, path+"/offer", token, webrtc.SDPTypeOffer)
		if err != nil {
			return err
		}
		if err := connection.SetRemoteDescription(offer); err != nil {
			return err
		}
		local, err = connection.CreateAnswer(nil)
	}
	if err != nil {
		return err
	}
	gathered := webrtc.GatheringCompletePromise(connection)
	if err := connection.SetLocalDescription(local); err != nil {
		return err
	}
	select {
	case <-gathered:
	case <-ctx.Done():
		return ctx.Err()
	}
	if err := server.publish(ctx, localPath, token, connection.LocalDescription()); err != nil {
		return err
	}
	if create {
		answer, err := server.wait(ctx, path+"/answer", token, webrtc.SDPTypeAnswer)
		if err != nil {
			return err
		}
		return connection.SetRemoteDescription(answer)
	}
	return nil
}

func bridge(ctx context.Context, server signaling, keys credentials, create bool, stun string, input io.Reader, output io.Writer) error {
	settings := webrtc.SettingEngine{}
	settings.DetachDataChannels()
	configuration := webrtc.Configuration{}
	if stun != "" {
		configuration.ICEServers = []webrtc.ICEServer{{URLs: []string{stun}}}
	}
	connection, err := webrtc.NewAPI(webrtc.WithSettingEngine(settings)).NewPeerConnection(configuration)
	if err != nil {
		return err
	}
	defer connection.Close()
	opened := make(chan io.ReadWriteCloser, 1)
	configure := func(channel *webrtc.DataChannel) {
		if channel.Label() != channelLabel || !channel.Ordered() ||
			channel.MaxRetransmits() != nil || channel.MaxPacketLifeTime() != nil {
			_ = channel.Close()
			return
		}
		channel.OnOpen(func() {
			stream, err := channel.Detach()
			if err != nil {
				return
			}
			select {
			case opened <- stream:
			default:
				_ = stream.Close()
			}
		})
	}
	if create {
		channel, err := connection.CreateDataChannel(channelLabel, nil)
		if err != nil {
			return err
		}
		configure(channel)
	} else {
		connection.OnDataChannel(configure)
	}
	if err := negotiate(ctx, connection, server, keys, create); err != nil {
		return err
	}
	var stream io.ReadWriteCloser
	select {
	case stream = <-opened:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer stream.Close()
	results := make(chan error, 2)
	copyChunks := func(dst io.Writer, src io.Reader) {
		// Wrap source so io.CopyBuffer cannot bypass the message-size bound via WriterTo.
		_, err := io.CopyBuffer(struct{ io.Writer }{dst}, struct{ io.Reader }{src}, make([]byte, chunkSize))
		results <- err
	}
	go copyChunks(stream, input)
	go copyChunks(output, stream)
	select {
	case err := <-results:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func run() error {
	mode := flag.String("mode", "", "create or join")
	base := flag.String("url", "", "trusted HTTPS signaling service")
	stun := flag.String("stun", "stun:stun.l.google.com:19302", "STUN URL, or empty for local tests")
	flag.Parse()
	if (*mode != "create" && *mode != "join") ||
		(*stun != "" && !strings.HasPrefix(*stun, "stun:")) {
		return errors.New("select create or join and an optional stun: URL")
	}
	server, err := newSignaling(*base)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	input := bufio.NewReaderSize(os.Stdin, 256)
	var keys credentials
	create := *mode == "create"
	if create {
		keys, err = server.create(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Share this private room code with the paired peer: %s.%s\n", keys.Room, keys.Responder)
	} else {
		line, err := input.ReadSlice('\n')
		if err != nil {
			return errors.New("expected a room code on standard input")
		}
		room, responder, _ := strings.Cut(strings.TrimSpace(string(line)), ".")
		if !validToken(room) || !validToken(responder) {
			return errors.New("invalid room code")
		}
		keys = credentials{Room: room, Responder: responder}
	}
	return bridge(ctx, server, keys, create, *stun, input, os.Stdout)
}

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
