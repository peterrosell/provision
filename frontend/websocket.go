package frontend

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/digitalrebar/logger"
	"github.com/digitalrebar/provision/models"
	"github.com/gin-gonic/gin"
	"gopkg.in/olahol/melody.v1"
)

var wsLock = &sync.Mutex{}

func (fe *Frontend) InitWebSocket() {
	fe.melody = melody.New()

	fe.ApiGroup.GET("/ws", func(c *gin.Context) {
		auth, _ := c.Get("DRP-AUTH")
		l, _ := c.Get("logger")
		keys := map[string]interface{}{
			"DRP-AUTH": auth,
			"logger":   l,
		}
		fe.melody.HandleRequestWithKeys(c.Writer, c.Request, keys)
	})

	fe.melody.HandleMessage(websocketHandler)
}

// Callers register or deregister values.
// type.action.key = with * as wildcard spots.

func wsFilterFunction(emap []string,
	auth *authBlob,
	e *models.Event) bool {
	// Check for an event to map.
	matched := false
	for _, test := range emap {
		arr := strings.SplitN(test, ".", 3)

		if arr[0] != "*" && arr[0] != e.Type {
			continue
		}
		if arr[1] != "*" && arr[1] != e.Action {
			continue
		}
		if arr[2] != "*" && arr[2] != e.Key {
			continue
		}
		matched = true
		break
	}

	// Make sure we are authorized to see this event.
	if matched && auth != nil {
		matched = auth.matchClaim(models.MakeRole("", e.Type, e.Action, e.Key).Compile())
	}
	return matched
}

func (f *Frontend) Publish(e *models.Event) error {
	if msg, err := json.Marshal(e); err != nil {
		return err
	} else {
		return f.melody.BroadcastFilter(msg, func(s *melody.Session) bool {
			var emap []string
			var auth *authBlob
			hasMap := func() bool {
				wsLock.Lock()
				defer wsLock.Unlock()
				if c := s.MustGet("DRP-AUTH"); c != nil {
					auth = c.(*authBlob)
				}
				if val, ok := s.Get("EventMap"); !ok {
					return false
				} else {
					tmap := val.([]string)
					emap = make([]string, len(tmap), len(tmap))
					for i, v := range tmap {
						emap[i] = v
					}
					return true
				}
			}()
			if !hasMap {
				return false
			}
			return wsFilterFunction(emap, auth, e)
		})
	}
}

// This never gets unloaded.
func (f *Frontend) Reserve() error {
	return nil
}
func (f *Frontend) Release() {}
func (f *Frontend) Unload()  {}

func websocketHandler(s *melody.Session, buf []byte) {
	l := s.MustGet("logger").(logger.Logger).NoPublish()
	splitMsg := bytes.SplitN(bytes.TrimSpace(buf), []byte(" "), 2)
	if len(splitMsg) != 2 {
		l.Warnf("WS: Unknown: Received message: %s\n", string(buf))
		return
	}
	prefix, msg := string(splitMsg[0]), string(splitMsg[1])
	if !(prefix == "register" || prefix == "deregister") {
		l.Warnf("WS: Invalid msg prefix %s", prefix)
		return
	}
	wsLock.Lock()
	defer wsLock.Unlock()
	val, ok := s.Get("EventMap")
	if !ok {
		val = []string{}
	}
	emap := val.([]string)
	event := &models.Event{Time: time.Now(), Type: "websocket", Action: prefix, Key: msg}
	switch prefix {
	case "register":
		found := false
		for _, test := range emap {
			if test == msg {
				found = true
				break
			}
		}
		if !found {
			l.Debugf("Registering for %s", msg)
			emap = append(emap, msg)
		}
	case "deregister":
		res := make([]string, 0, len(emap))
		for _, test := range emap {
			if test == msg {
				l.Debugf("Deregistering %s", msg)
				continue
			}
			res = append(res, test)
		}
		emap = res
	}
	// Send event to wake up caller.
	if jmsg, err := json.Marshal(event); err == nil {
		if err := s.Write(jmsg); err != nil {
			l.Errorf("Failed to write websocket registration event: %v, %v\n", event, err)
		}
	} else {
		l.Errorf("Failed to marshal websocket registration event: %v, %v\n", event, err)
	}
	s.Set("EventMap", emap)
}
