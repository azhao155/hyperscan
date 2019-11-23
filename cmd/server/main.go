package main

import (
	"azwaf/grpc"
	"azwaf/waf"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
)

func main() {
	rand.Seed(time.Now().UnixNano())

	// Command line args
	logLevel := flag.String("loglevel", "error", "sets log level. Can be one of: debug, info, warn, error, fatal, panic.")
	profiling := flag.Bool("profiling", false, "whether to enable the :6060/debug/pprof/ endpoint")
	secruleconf := flag.String("secruleconf", "", "if set, use the given SecRule config file instead of using the ConfigMgr service")
	limitsArg := flag.String("bodylimits", "", fmt.Sprintf("if set, use these request body length limits. Unit is bytes. These are only enforced within around 8KiB precision, due to various default buffer sizes. This parameter takes multiple integer values: max length of any single field, max length of request bodies excluding file fields in multipart/form-data bodies, max total request body length, max total request body length when content-type is application/x-www-form-urlencoded and there is a SecRule using REQUEST_BODY. Example (these are the defaults): -bodylimits=%v,%v,%v,%v ", waf.DefaultLengthLimits.MaxLengthField, waf.DefaultLengthLimits.MaxLengthPausable, waf.DefaultLengthLimits.MaxLengthTotal, waf.DefaultLengthLimits.MaxLengthTotalFullRawRequestBody))
	flag.Parse()
	standaloneSecruleServer := *secruleconf != ""

	// Start profiling server if enabled
	if *profiling {
		go func() {
			http.ListenAndServe(":6060", nil)
		}()
	}

	loglevel, _ := zerolog.ParseLevel(*logLevel)
	logger := zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).Level(loglevel).With().Timestamp().Caller().Logger()
	lengthLimits := parseLengthLimitsArgOrDefault(logger, *limitsArg)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR1)

	reopenLogFileChan := make(chan bool)
	go func() {
		for {
			<-signalChan
			reopenLogFileChan <- true
		}
	}()

	grpc.StartServer(logger, *secruleconf, lengthLimits, standaloneSecruleServer, "tcp", ":37291", reopenLogFileChan)
}

func parseLengthLimitsArgOrDefault(logger zerolog.Logger, limitsArg string) (lengthLimits waf.LengthLimits) {
	lengthLimits = waf.DefaultLengthLimits

	if limitsArg != "" {
		nn := strings.Split(limitsArg, ",")
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
