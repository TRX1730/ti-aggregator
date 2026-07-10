package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed web
var staticFiles embed.FS

type server struct {
	db  *pgxpool.Pool
	hub *hub
}

func main() {
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("brak DATABASE_URL")
	}

	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("nie mogę utworzyć puli połączeń: %v", err)
	}
	defer pool.Close()

	srv := &server{db: pool, hub: newHub()}
	go srv.runListener(context.Background(), dbURL)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.healthHandler)
	mux.HandleFunc("POST /iocs", srv.createIOC)
	mux.HandleFunc("GET /iocs/{id}", srv.getIOC)
	mux.HandleFunc("GET /iocs", srv.listIOCs)
	mux.HandleFunc("GET /iocs/{id}/pivots", srv.getPivots)
	mux.HandleFunc("GET /export/stix", srv.exportSTIX)
	mux.HandleFunc("POST /import", srv.importLogs)
	mux.HandleFunc("GET /events", srv.eventsHandler)

	webRoot, err := fs.Sub(staticFiles, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /", http.FileServerFS(webRoot))

	addr := ":" + port
	log.Printf("API startuje na %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

func (s *server) healthHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	status := "ok"
	dbStatus := "ok"
	httpCode := http.StatusOK

	if err := s.db.Ping(ctx); err != nil {
		status = "degraded"
		dbStatus = "unreachable"
		httpCode = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(map[string]string{
		"status": status,
		"db":     dbStatus,
	})
}
