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

// go:embed wkompilowuje pliki z folderu web/ w binarkę serwera.
// Dzięki temu API serwuje frontend bez dodatkowych plików w kontenerze.
//
//go:embed web
var staticFiles embed.FS

// server trzyma zależności, których potrzebują handlery — na razie tylko bazę.
// Dzięki temu handlery mają dostęp do bazy przez s.db, bez zmiennych globalnych.
type server struct {
	db  *pgxpool.Pool
	hub *hub // rozsyła zdarzenia SSE do przeglądarek
}

func main() {
	port := os.Getenv("API_PORT")
	if port == "" {
		port = "8080"
	}

	// Adres bazy dostajemy ze zmiennej środowiskowej (ustawiamy ją w docker-compose).
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("brak DATABASE_URL")
	}

	// pgxpool.New tworzy PULĘ połączeń do Postgresa.
	// Pula = zestaw gotowych połączeń wielokrotnego użytku (szybciej niż łączyć się za każdym razem).
	pool, err := pgxpool.New(context.Background(), dbURL)
	if err != nil {
		log.Fatalf("nie mogę utworzyć puli połączeń: %v", err)
	}
	defer pool.Close() // zamknij pulę, gdy program się kończy

	srv := &server{db: pool, hub: newHub()}

	// Goroutine nasłuchująca NOTIFY z Postgresa i rozsyłająca do przeglądarek.
	go srv.runListener(context.Background(), dbURL)

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", srv.healthHandler)
	mux.HandleFunc("POST /iocs", srv.createIOC)
	mux.HandleFunc("GET /iocs/{id}", srv.getIOC)
	mux.HandleFunc("GET /iocs", srv.listIOCs)
	mux.HandleFunc("GET /iocs/{id}/pivots", srv.getPivots) // powiązania
	mux.HandleFunc("GET /export/stix", srv.exportSTIX)     // eksport STIX 2.1
	mux.HandleFunc("POST /import", srv.importLogs)         // import IOC z logów
	mux.HandleFunc("GET /events", srv.eventsHandler)       // strumień SSE

	// Serwujemy frontend spod "/". Trasy API wyżej są bardziej szczegółowe,
	// więc mają pierwszeństwo — "/" łapie całą resztę (index.html itd.).
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

// healthHandler mówi teraz DWIE rzeczy: że backend żyje ORAZ czy baza jest osiągalna.
func (s *server) healthHandler(w http.ResponseWriter, r *http.Request) {
	// Kontekst z limitem czasu: dajemy bazie max 2 sekundy na odpowiedź,
	// żeby jedno zawieszone połączenie nie blokowało nas w nieskończoność.
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	status := "ok"
	dbStatus := "ok"
	httpCode := http.StatusOK

	// Ping wysyła do bazy najprostsze możliwe zapytanie, żeby sprawdzić, czy odpowiada.
	if err := s.db.Ping(ctx); err != nil {
		status = "degraded"
		dbStatus = "unreachable"
		httpCode = http.StatusServiceUnavailable // 503 = usługa częściowo niedostępna
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpCode)
	json.NewEncoder(w).Encode(map[string]string{
		"status": status,
		"db":     dbStatus,
	})
}
