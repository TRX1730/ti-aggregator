package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

type hub struct {
	mu   sync.Mutex
	subs map[chan string]struct{}
}

func newHub() *hub {
	return &hub{subs: make(map[chan string]struct{})}
}

func (h *hub) subscribe() chan string {
	ch := make(chan string, 16)
	h.mu.Lock()
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	return ch
}

func (h *hub) unsubscribe(ch chan string) {
	h.mu.Lock()
	delete(h.subs, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *hub) broadcast(msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.subs {
		select {
		case ch <- msg:
		default:
		}
	}
}

func (s *server) runListener(ctx context.Context, dbURL string) {
	for {
		conn, err := pgx.Connect(ctx, dbURL)
		if err != nil {
			log.Printf("listener: nie mogę się połączyć: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		if _, err := conn.Exec(ctx, "LISTEN enrichments"); err != nil {
			log.Printf("listener: LISTEN nieudany: %v", err)
			conn.Close(ctx)
			time.Sleep(2 * time.Second)
			continue
		}
		log.Printf("listener: nasłuchuję kanału 'enrichments'")

		for {
			n, err := conn.WaitForNotification(ctx)
			if err != nil {
				log.Printf("listener: przerwane (%v), łączę ponownie", err)
				break
			}
			s.hub.broadcast(n.Payload)
		}
		conn.Close(ctx)
		time.Sleep(time.Second)
	}
}

func (s *server) eventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming nieobsługiwany", http.StatusInternalServerError)
		return
	}

	ch := s.hub.subscribe()
	defer s.hub.unsubscribe(ch)

	fmt.Fprint(w, ": połączono\n\n")
	flusher.Flush()

	ctx := r.Context()
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case iocID := <-ch:
			fmt.Fprintf(w, "event: enrichment\ndata: %s\n\n", iocID)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}
