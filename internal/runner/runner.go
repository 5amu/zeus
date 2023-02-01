package runner

import (
	"sync"

	"github.com/5amu/zeus/pkg/connections"
	"github.com/5amu/zeus/pkg/core"
	"github.com/5amu/zeus/pkg/plugins"
	"github.com/projectdiscovery/gologger"
)

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
