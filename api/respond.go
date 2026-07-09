package main

import (
	"encoding/json"
	"net/http"
)

// writeJSON wysyła dowolną wartość jako JSON z podanym kodem HTTP.
// "any" znaczy "dowolny typ" (to alias na interface{}).
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// writeError wysyła komunikat błędu w jednolitym formacie: {"error": "..."}
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
