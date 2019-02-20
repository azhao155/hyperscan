package main

import (
	"azwaf/server"
	"log"
)

func main() {
	log.Print("Starting WAF server")
	server.Start()
}
