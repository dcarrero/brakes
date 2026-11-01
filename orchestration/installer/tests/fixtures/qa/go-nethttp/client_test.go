package main

import "net/http"

func helper() { http.HandleFunc("/x", nil) }
