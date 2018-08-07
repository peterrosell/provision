package backend

import (
	"log"
	"sync"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
)

/*
 * NOTE: CRUCIAL: CRITICAL: This could be bad if not adhered.
 * The Publish, release, and reserve routines must not call loggers
 * that publish events!
 */
type Publisher interface {
	Publish(event *models.Event) error
	Reserve() error
	Release()
	Unload()
}

func SetLogPublisher(l *logger.Buffer, pubs *Publishers) {
	l.SetPublisher(func(l *logger.Line) {
		pubs.publish("log", l.Level.String(), l.Service, l.Principal, l)
	})
}

type Publishers struct {
	pubs   []Publisher
	logger *log.Logger
	lock   sync.Mutex
}

func NewPublishers(logger *log.Logger) *Publishers {
	return &Publishers{logger: logger, pubs: make([]Publisher, 0, 0)}
}

func (p *Publishers) Add(pp Publisher) {
	p.lock.Lock()
	defer p.lock.Unlock()

	p.pubs = append(p.pubs, pp)
}

func (p *Publishers) Remove(pp Publisher) {
	p.lock.Lock()
	for i, ppp := range p.pubs {
		if ppp == pp {
			p.pubs = append(p.pubs[:i], p.pubs[i+1:]...)
			break
		}
	}
	p.lock.Unlock()

	pp.Unload()
}

func (p *Publishers) List() []Publisher {
	p.lock.Lock()
	defer p.lock.Unlock()

	newPubs := make([]Publisher, 0, 0)
	for _, pub := range p.pubs {
		newPubs = append(newPubs, pub)
	}

	return newPubs
}

func (p *Publishers) publish(t, a, k, pr string, o interface{}) error {
	e := &models.Event{
		Time:      time.Now(),
		Type:      t,
		Action:    a,
		Key:       k,
		Principal: pr,
		Object:    o}
	return p.publishEvent(e)
}

func (p *Publishers) publishEvent(e *models.Event) error {
	newPubs := make([]Publisher, 0, 0)
	p.lock.Lock()
	for _, pub := range p.pubs {
		if err := pub.Reserve(); err == nil {
			newPubs = append(newPubs, pub)
		}
	}
	p.lock.Unlock()

	for _, pub := range newPubs {
		if err := pub.Publish(e); err != nil {
			p.logger.Printf("Failed to Publish event on %#v: %#v\n", pub, err)
		}
		pub.Release()
	}

	return nil
}
