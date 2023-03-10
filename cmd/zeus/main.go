package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/5amu/zeus/pkg/connections"
	"github.com/5amu/zeus/pkg/core"
	"github.com/5amu/zeus/pkg/plugins"
	"github.com/5amu/zeus/pkg/utils"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
)

const Version = "0.3"

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
	flagSet.SetDescription(`Fast and reliable local vulnerability scanner over remote connection`)

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

type ZeusResults struct {
	Plugins []*plugins.Plugin               `json:"plugins"`
	Targets []*connections.ConnectionString `json:"targets"`
	Results []*ZeusSingleResult             `json:"results"`
}

type ZeusSingleResult struct {
	Target        string                  `json:"target"`
	PluginResults []*plugins.PluginResult `json:"plugin_results"`
}

type Factory struct {
	targets       []*connections.ConnectionString
	plugins       []*plugins.Plugin
	threads       int
	singleResults []*ZeusSingleResult
	mutexResults  sync.Mutex
}

func NewFactory(targets []*connections.ConnectionString, pluginList []*plugins.Plugin, threads int) *Factory {
	return &Factory{
		targets: targets,
		plugins: pluginList,
		threads: threads,
	}
}

func notificationPrinter(engine *core.Engine) {
	for {
		msg := <-engine.GetNotification()
		gologger.Warning().Label("FINDING").Msgf("[%v] %v (%v)", msg.Host, msg.PluginID, msg.Severity)
	}
}

func (f *Factory) Start() (*ZeusResults, error) {
	gologger.Info().Msg("assessment is starting")

	// Prepare for concurrency
	var wg sync.WaitGroup
	guard := make(chan struct{}, f.threads)

	// Prepare the engine with a printer for notifications
	eng := core.NewEngineWithPlugins(f.plugins)
	go eng.NotificationServer()
	go notificationPrinter(eng)
	for _, cs := range f.targets {
		conn, err := connections.NewConnection(cs)
		if err != nil {
			gologger.Error().Msgf("%v", err)
			continue
		}

		guard <- struct{}{}
		wg.Add(1)
		gologger.Debug().Msgf("running on %v", (*conn).String())

		go func(c *connections.Connection) {
			result, err := eng.RunOnConnection(c)
			if err != nil {
				gologger.Error().Msgf("[%v]: %v", (*c).String(), err)
				<-guard
				wg.Done()
				return
			}
			f.mutexResults.Lock()
			f.singleResults = append(f.singleResults, &ZeusSingleResult{
				Target:        (*c).String(),
				PluginResults: result,
			})
			f.mutexResults.Unlock()
			<-guard
			wg.Done()
		}(conn)
	}
	wg.Wait()

	gologger.Info().Msg("assessment is over")
	return &ZeusResults{
		Plugins: f.plugins,
		Targets: f.targets,
		Results: f.singleResults,
	}, nil
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

	if args.pluginPath == "" {
		gologger.Fatal().Msg("no plugin was provided")
	}

	pluginList, err := utils.ReadPluginsFromDirectory(args.pluginPath)
	if err != nil {
		gologger.Fatal().Msgf("%v", err)
	}
	if len(pluginList) == 0 {
		gologger.Fatal().Msg("no plugin was provided")
	}

	results, err := NewFactory(targets, pluginList, args.threads).Start()
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
