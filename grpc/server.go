package grpc

import (
	sreng "azwaf/secrule/engine"
	srrs "azwaf/secrule/reqscanning"
	srre "azwaf/secrule/ruleevaluation"
	srrp "azwaf/secrule/ruleparsing"

	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/geodb"
	"azwaf/hyperscan"
	"azwaf/ipreputation"
	"azwaf/logging"
	"azwaf/waf"

	"github.com/rs/zerolog"
)

// StartServer is the dependency injection composition root for running Azwaf through gRPC
func StartServer(logger zerolog.Logger, secruleconf string, lengthLimits waf.LengthLimits, standaloneSecruleServer bool, network string, address string, reopenLogFileCh chan bool, reopenLogFileChForShaodowMode chan bool) {
	// Initialize common dependencies
	rlf, err := logging.NewFileLogResultsLoggerFactory(&logging.LogFileSystemImpl{}, logger, reopenLogFileCh, logging.FileName)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating file logger")
	}

	srlf, err := logging.NewFileLogResultsLoggerFactory(&logging.LogFileSystemImpl{}, logger, reopenLogFileChForShaodowMode, logging.ShadowModeFileName)
	if err != nil {
		logger.Fatal().Err(err).Msg("Error while creating file logger")
	}

	p := srrp.NewRuleParser()
	rlfs := srrp.NewRuleLoaderFileSystem()
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := srrs.NewReqScannerFactory(mref)
	ref := srre.NewRuleEvaluatorFactory()

	// Initialize a WAF server, either via config manager, or standalone just with a SecRule engine
	var wafServer waf.Server
	if standaloneSecruleServer {
		logger.Info().Str("secruleconf", secruleconf).Msg("Creating a standalone WAF with a SecRule engine")

		srl := srrp.NewStandaloneRuleLoader(p, rlfs, secruleconf)
		stmts, err := srl.Rules()
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while loading rules")
		}

		sre, err := sreng.NewEngine(stmts, rsf, ref, "", nil) // TODO some sensible ruleSetID?
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating SecRule engine")
		}

		rbp := bodyparsing.NewRequestBodyParser(lengthLimits)

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
		rl := srrp.NewCrsRuleLoader(p, rlfs)
		sref := sreng.NewEngineFactory(logger, rl, rsf, ref)
		ire := ipreputation.NewIPReputationEngine(&ipreputation.FileSystemImpl{})

		maxInt32 := 2147483647
		rbp := bodyparsing.NewRequestBodyParser(waf.LengthLimits{
			MaxLengthField:                   maxInt32,
			MaxLengthPausable:                maxInt32,
			MaxLengthTotal:                   maxInt32,
			MaxLengthTotalFullRawRequestBody: maxInt32,
		})

		wafServer, err = waf.NewServer(logger, cm, c, rlf, srlf, sref, rbp, cref, ire, geoDB)
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
