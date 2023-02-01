package core

import (
	"sync"
	"time"

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
	plugins             []*plugins.Plugin
	results             []*plugins.PluginResult
	notifications       []Notification
	notificationChannel chan Notification
	mutexNotification   sync.Mutex
}

func NewEngineWithPlugins(plugins []*plugins.Plugin) *Engine {
	return &Engine{
		plugins:             plugins,
		notificationChannel: make(chan Notification),
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
			e.mutexNotification.Lock()
			e.notifications = append(e.notifications, Notification{
				Host:     (*con).String(),
				Severity: p.Severity,
				PluginID: p.ID,
			})
			e.mutexNotification.Unlock()
		}
		e.results = append(e.results, result)
	}
	return e.results, nil
}

func (e *Engine) NotificationServer() {
	for {
		if len(e.notifications) == 0 {
			// Wait until a notification appears
			time.After(1 * time.Second)
			continue
		}

		e.mutexNotification.Lock()
		if len(e.notifications) == 0 {
			e.mutexNotification.Unlock()
			continue
		}
		notification := e.notifications[0]
		// remove the first element from slice: https://stackoverflow.com/a/57213476
		// https://play.golang.org/p/mYaU_Oobzs2
		e.notifications = append(e.notifications[:0], e.notifications[1:]...)
		e.mutexNotification.Unlock()
		e.notificationChannel <- notification
	}
}

func (e *Engine) GetNotification() <-chan Notification {
	return e.notificationChannel
}
