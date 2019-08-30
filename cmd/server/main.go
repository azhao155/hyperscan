package main

import (
	"azwaf/bodyparsing"
	"azwaf/customrule"
	"azwaf/grpc"
	"azwaf/hyperscan"
	"azwaf/logging"
	"azwaf/secrule"
	"azwaf/waf"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

// Dependency injection composition root
func main() {
	rand.Seed(time.Now().UnixNano())

	// Command line args
	logLevel := flag.String("loglevel", "error", "sets log level. Can be one of: debug, info, warn, error, fatal, panic.")
	profiling := flag.Bool("profiling", false, "whether to enable the :6060/debug/pprof/ endpoint")
	secruleconf := flag.String("secruleconf", "", "if set, use the given SecRule config file instead of using the ConfigMgr service")
	limitsArg := flag.String("bodylimits", "", fmt.Sprintf("if set, use these request body length limits. Unit is bytes. These are only enforced within around 8KiB precision, due to various default buffer sizes. This parameter takes three integer values: max length of any single field, max length of request bodies excluding file fields in multipart/form-data bodies, and max total request body length. Example (these are the defaults): -limits=%v,%v,%v ", defaultLengthLimits.MaxLengthField, defaultLengthLimits.MaxLengthPausable, defaultLengthLimits.MaxLengthTotal))
	flag.Parse()
	standaloneSecruleServer := *secruleconf != ""

	// Start profiling server if enabled
	if *profiling {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	}

	// Initialize common dependencies
	loglevel, _ := zerolog.ParseLevel(*logLevel)
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()
	secruleResLog, wafResLog := logging.NewZerologResultsLogger(logger)
	lengthLimits := parseLengthLimitsArgOrDefault(logger, limitsArg)
	rbp := bodyparsing.NewRequestBodyParser(lengthLimits)
	p := secrule.NewRuleParser()
	rlfs := secrule.NewRuleLoaderFileSystem()
	hsfs := hyperscan.NewCacheFileSystem()
	hscache := hyperscan.NewDbCache(hsfs)
	mref := hyperscan.NewMultiRegexEngineFactory(hscache)
	rsf := secrule.NewReqScannerFactory(mref)
	re := secrule.NewRuleEvaluator()

	// Initialize a WAF server, either via config manager, or standalone just with a SecRule engine
	var wafServer waf.Server
	if standaloneSecruleServer {
		logger.Info().Str("secruleconf", *secruleconf).Msg("Creating a standalone WAF with a SecRule engine")

		srl := secrule.NewStandaloneRuleLoader(p, rlfs, *secruleconf)
		stmts, err := srl.Rules()
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while loading rules")
		}

		sre, err := secrule.NewEngine(stmts, rsf, re, secruleResLog)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating SecRule engine")
		}

		wafServer, err = waf.NewStandaloneSecruleServer(logger, sre, rbp, wafResLog)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating standalone SecRule engine WAF")
		}
	} else {
		// TODO Implement config manager config restore and pass restored config to NewServer. Also pass the config mgr to the grpc NewServer
		cm, c, err := waf.NewConfigMgr(&waf.ConfigFileSystemImpl{}, &grpc.ConfigConverterImpl{})
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating config manager")
		}

		rl := secrule.NewCrsRuleLoader(p, rlfs)
		sref := secrule.NewEngineFactory(logger, rl, rsf, re, secruleResLog)
		crl := customrule.NewCustomRuleLoader()
		cref := customrule.NewEngineFactory(logger, crl, rsf, re)

		wafServer, err = waf.NewServer(logger, cm, c, sref, rbp, wafResLog, cref)
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while creating service manager")
		}
	}

	// Start the gRPC server using the given WAF server
	grpcServer := grpc.NewServer(logger, wafServer)
	logger.Info().Msg("Starting gRPC WAF server")
	if err := grpcServer.Serve(); err != nil {
		logger.Fatal().Err(err).Msg("Error while running gRPC WAF server")
	}
}

var defaultLengthLimits = waf.LengthLimits{
	MaxLengthField:    1024 * 20,         // 20 KiB
	MaxLengthPausable: 1024 * 128,        // 128 KiB
	MaxLengthTotal:    1024 * 1024 * 700, // 700 MiB
}

func parseLengthLimitsArgOrDefault(logger zerolog.Logger, limitsArg *string) (lengthLimits waf.LengthLimits) {
	lengthLimits = defaultLengthLimits

	if *limitsArg != "" {
		nn := strings.Split(*limitsArg, ",")
		if len(nn) != 3 {
			logger.Fatal().Msg("The limits arg must contain exactly 3 comma separated integer values")
		}

		n, err := strconv.Atoi(nn[0])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 1")
		}
		lengthLimits.MaxLengthField = n

		n, err = strconv.Atoi(nn[1])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 2")
		}
		lengthLimits.MaxLengthPausable = n

		n, err = strconv.Atoi(nn[2])
		if err != nil {
			logger.Fatal().Err(err).Msg("Error while parsing limits arg 3")
		}
		lengthLimits.MaxLengthTotal = n
	}

	return
}
