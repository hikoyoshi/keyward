// This is a fake-data UI walkthrough, not the password manager or its broker.
package main

import (
	"embed"
	"log"
	"net/http"
	"time"
)

//go:embed index.html style.css app.js
var assets embed.FS

func main() {
	server := &http.Server{
		Addr:              "127.0.0.1:8716",
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Host != "127.0.0.1:8716" && r.Host != "localhost:8716" {
				http.Error(w, "invalid host", http.StatusForbidden)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'none'; frame-ancestors 'none'; form-action 'none'")
			http.FileServer(http.FS(assets)).ServeHTTP(w, r)
		}),
	}
	log.Println("Fake-data walkthrough: http://127.0.0.1:8716 (no real credentials)")
	log.Fatal(server.ListenAndServe())
}
