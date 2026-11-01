package main

import (
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/livez", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	log.Fatal(http.ListenAndServe(":8080", nil))
}
