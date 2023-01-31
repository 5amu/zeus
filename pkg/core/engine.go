package core

import (
	"github.com/5amu/zeus/pkg/connections"
	"github.com/5amu/zeus/pkg/plugins"
)

type Notification struct {
	Host     string
	Severity string
	PluginID string
}

// Engine is configuration wrapper for the execution
type Engine struct {
	plugins      []*plugins.Plugin
	threads      int
	results      []*plugins.PluginResult
	notification chan Notification
	stop         chan struct{}
}

func NewEngineWithPlugins(plugins []*plugins.Plugin, threads int) *Engine {
	return &Engine{
		plugins:      plugins,
		threads:      threads,
		notification: make(chan Notification, len(plugins)),
		stop:         make(chan struct{}, 1),
	}
}

func (e *Engine) sendToNotificationChannel(host string, plugin *plugins.Plugin) {
	e.notification <- Notification{
		Host:     host,
		Severity: plugin.Severity,
		PluginID: plugin.ID,
	}
}

func (e *Engine) RunOnConnection(con *connections.Connection) ([]*plugins.PluginResult, error) {
	e.results = make([]*plugins.PluginResult, len(e.plugins))
	for _, p := range e.plugins {
		result, err := p.RunTests(con)
		if err != nil {
			return nil, err
		}
		if result.IsVulnerable {
			e.sendToNotificationChannel((*con).String(), p)
		}
		e.results = append(e.results, result)
	}
	return e.results, nil
}

func (e *Engine) GetNotification() <-chan Notification {
	return e.notification
}
