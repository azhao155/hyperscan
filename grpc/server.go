package grpc

import (
	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/geodb"
	"azwaf/hyperscan"
	"azwaf/ipreputation"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"

	"github.com/rs/zerolog"
)

// StartServer is the dependency injection composition root for running Azwaf through gRPC
func StartServer(logger zerolog.Logger, secruleconf string, lengthLimits waf.LengthLimits, standaloneSecruleServer bool, network string, address string, reopenLogFileCh chan bool) {
	// Initialize common dependencies
	rlf, err := logging.NewFileLogResultsLoggerFactory(&logging.LogFileSystemImpl{}, logger, reopenLogFileCh)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating file logger")
	}

	rbp := bodyparsing.NewRequestBodyParser(lengthLimits)
	p := secrule.NewRuleParser()
	rlfs := secrule.NewRuleLoaderFileSystem()
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	ref := secrule.NewRuleEvaluatorFactory()

	// Initialize a WAF server, either via config manager, or standalone just with a SecRule engine
	var wafServer waf.Server
	if standaloneSecruleServer {
		logger.Info().Str("secruleconf", secruleconf).Msg("Creating a standalone WAF with a SecRule engine")

		srl := secrule.NewStandaloneRuleLoader(p, rlfs, secruleconf)
		stmts, err := srl.Rules()
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while loading rules")
		}

		sre, err := secrule.NewEngine(stmts, rsf, ref, "") // TODO some sensible ruleSetID?
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating SecRule engine")
		}

		wafServer, err = waf.NewStandaloneSecruleServer(logger, rlf, sre, rbp)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating standalone SecRule engine WAF")
		}
	} else {
		// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
		cm, c, err := waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &ConfigConverterImpl{})
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating config manager")
		}

		gfs := geodb.NewGeoIPFileSystem(logger)
		geoDB := geodb.NewGeoDB(logger, gfs)
		cref := customrule.NewEngineFactory(mref, geoDB)
		rl := secrule.NewCrsRuleLoader(p, rlfs)
		sref := secrule.NewEngineFactory(logger, rl, rsf, ref)
		ire := ipreputation.NewIPReputationEngine(&ipreputation.FileSystemImpl{})

		wafServer, err = waf.NewServer(logger, cm, c, rlf, sref, rbp, cref, ire, geoDB)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating service manager")
		}
	}

	// Start the gRPC server using the given WAF server
	grpcServer := newServer(logger, wafServer)
	logger.Info().Msg("Starting gRPC WAF server")
	if err := grpcServer.Serve(network, address); err != nil {
		logger.Fatal().Err(err).Msg("Error while running gRPC WAF server")
	}
}
