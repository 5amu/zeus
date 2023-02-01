package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/5amu/zeus/internal/runner"
	"github.com/5amu/zeus/pkg/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const Version = "0.1"

type arguments struct {
	version        bool
	verbose        bool
	validatePlugin string
	outfile        string
	pluginPath     string
	target         string
	targetFile     string
	threads        int
}

func parseCLI() (*arguments, error) {
	var args arguments

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`Last and reliable local vulnerability scanner over remote connection`)

	flagSet.CreateGroup("input", "Target",
		flagSet.StringVarP(&args.target, "target", "u", "", "target host to scan"),
		flagSet.StringVarP(&args.targetFile, "list", "l", "", "file containing targets to scan"),
	)
	flagSet.CreateGroup("output", "Output",
		flagSet.BoolVarP(&args.verbose, "verbose", "v", false, "set output to verbose"),
		flagSet.StringVarP(&args.outfile, "output", "o", "", "set output file"),
	)
	flagSet.CreateGroup("plugins", "Plugins",
		flagSet.StringVarP(&args.validatePlugin, "validate", "vp", "", "validate specified plugin"),
		flagSet.StringVarP(&args.pluginPath, "plugin-path", "p", "", "path to get plugins from"),
	)
	flagSet.CreateGroup("debug", "Debug",
		flagSet.BoolVarP(&args.version, "version", "V", false, "show version and exit"),
		flagSet.IntVarP(&args.threads, "threads", "t", 4, "set the number of concurrent hosts to scan"),
	)

	return &args, flagSet.Parse()
}

func main() {
	args, err := parseCLI()
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}

	// If -V print version and exit
	if args.version {
		fmt.Println("Zeus version: " + Version)
		os.Exit(0)
	}

	// Set output verbosity
	gologger.DefaultLogger.SetMaxLevel(levels.LevelWarning)
	if args.verbose {
		gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)
	}
	gologger.Debug().Msg("logger level set to debug")

	// If the validation of a single plugin is asked, then the validation
	// of a single plugin will be given :)
	if args.validatePlugin != "" {
		if err := utils.ValidateSinglePlugin(args.validatePlugin); err != nil {
			gologger.Fatal().Msgf("%v", err)
		}
		gologger.Info().Msgf("plugin: %v is valid", args.validatePlugin)
		os.Exit(0)
	}

	targets, err := utils.ReadTargetsFromString(args.target)
	if args.targetFile != "" {
		targets, err = utils.ReadTargetsFromFile(args.targetFile)
	}
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}

	if len(targets) == 0 {
		gologger.Fatal().Msg("no target was provided")
	}

	pluginList, err := utils.ReadPluginsFromDirectory(args.pluginPath)
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}
	if len(pluginList) == 0 {
		gologger.Fatal().Msg("no plugin was provided")
	}

	results, err := runner.NewFactory(targets, pluginList, args.threads).Start()
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}

	if args.outfile != "" {
		data, err := json.Marshal(results)
		if err != nil {
			gologger.Fatal().Msgf("%v", err)
		}
		if err := os.WriteFile(args.outfile, data, 0644); err != nil {
			gologger.Fatal().Msgf("%v", err)
		}
	}
}
