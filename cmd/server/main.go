package main

import (
	"azwaf/config"
	"azwaf/grpc"
	"azwaf/secrule"
	"azwaf/waf"

	"encoding/json"
	"log"
)

func main() {
	// TODO Implement real config loading.
	c := &config.Main{}
	json.Unmarshal([]byte(`
		{
			"Sites": [
				{
					"Name": "site1"
				},
				{
					"Name": "site2"
				}
			]
		}
	`), c)

	// Depedency injection composition root
	sref := secrule.NewEngineFactory()
	w := waf.NewServer(c, sref)
	s := grpc.NewServer(w)

	log.Print("Starting WAF server")
	if err := s.Serve(); err != nil {
		log.Fatalf("%v", err.Error())
	}
}
