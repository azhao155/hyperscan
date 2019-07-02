package main

import (
	"azwaf/config"
	"azwaf/grpc"
	"azwaf/hyperscan"
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
					"Name": "site1",
					"RuleSet": "OWASP CRS 3.0"
				}
			]
		}
	`), c)

	// Depedency injection composition root
	p := secrule.NewRuleParser()
	rl := secrule.NewCrsRuleLoader(p)
	mref := hyperscan.NewMultiRegexEngineFactory()
	rsf := secrule.NewReqScannerFactory(mref)
	sref := secrule.NewEngineFactory(rl, rsf)

	// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
	w, err := waf.NewServer(c, sref)
	if err != nil {
		log.Fatalf("Error: %v", err)
	}

	s := grpc.NewServer(w)

	log.Print("Starting WAF server")
	if err := s.Serve(); err != nil {
		log.Fatalf("%v", err)
	}
}
