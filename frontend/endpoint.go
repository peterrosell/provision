package frontend

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"github.com/digitalrebar/provision/backend"
	"github.com/digitalrebar/provision/backend/index"
	"github.com/digitalrebar/provision/models"
	"github.com/galthaus/gzip"
	"github.com/gin-gonic/gin"
)

func (fe *Frontend) getEndpoint(c *gin.Context, id string) *backend.RawModel {
	ots := fe.dt.GetObjectTypes()
	found := false
	for _, ot := range ots {
		if ot == "endpoints" {
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	rt := fe.rt(c, "endpoints")
	var res *backend.RawModel
	params := map[string][]string{
		"HaId": []string{id},
	}
	rt.Do(func(d backend.Stores) {
		ref := &backend.RawModel{RawModel: &models.RawModel{"Type": "endpoints"}}
		filters, err := fe.processFilters(rt, d, ref, params)
		if err != nil {
			return
		}
		mainIndex := &d(ref.Prefix()).Index
		idx, err := index.All(filters...)(mainIndex)
		if err != nil {
			return
		}

		items := idx.Items()
		for _, item := range items {
			res = item.(*backend.RawModel)
			return
		}
	})
	return res
}

func (fe *Frontend) getEndpointUrl(c *gin.Context, id, rest string) (string, string, bool) {
	nrest := rest
	done := false
	for !done {
		res := fe.getEndpoint(c, id)
		if res == nil {
			// Couldn't find the id
			break
		}

		e, _ := res.GetStringField("Manager")
		if e == "" {
			p := res.GetParams()

			s, ok := p["manager/forward-url"].(string)
			if ok && s != "" {
				return s, nrest, ok
			}
			s, ok = p["manager/url"].(string)
			return s, nrest, ok
		}

		// is this owned by me?
		for _, myid := range fe.DrpIds {
			if e == myid {
				p := res.GetParams()
				s, ok := p["manager/forward-url"].(string)
				if ok && s != "" {
					return s, nrest, ok
				}
				s, ok = p["manager/url"].(string)
				return s, nrest, ok
			}
		}

		// Recurse to owner
		id = e
		nrest = ""
	}
	return "", rest, false
}

var proxyMap map[string]*httputil.ReverseProxy = map[string]*httputil.ReverseProxy{}
var proxyMutex = &sync.Mutex{}

func (fe *Frontend) forwardRequest(c *gin.Context, id, rest string, newBody interface{}) bool {
	if ep, nrest, ok := fe.getEndpointUrl(c, id, rest); ok {
		// parse the url
		turl, _ := url.Parse(ep)

		// reuse/create the reverse proxy
		proxyMutex.Lock()
		proxy, ok := proxyMap[turl.String()]
		if !ok {
			proxy = httputil.NewSingleHostReverseProxy(turl)
			proxy.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // client uses self-signed cert
			}
			proxyMap[turl.String()] = proxy
		}
		proxyMutex.Unlock()

		// Update the headers to allow for SSL redirection
		req := c.Request
		req.URL.Host = turl.Host
		req.URL.Scheme = turl.Scheme
		if nrest != "" {
			req.URL.Path = nrest
		}
		req.Header.Set("X-Forwarded-Host", req.Header.Get("Host"))
		req.Header.Set("Connection", "close")
		req.Host = turl.Host
		req.Close = true

		if newBody != nil {
			jstr, jerr := json.Marshal(newBody)
			if jerr != nil {
				err := &models.Error{
					Model:    "endpoints", // XXX: This is not right.
					Key:      id,
					Code:     http.StatusBadRequest,
					Type:     c.Request.Method,
					Messages: []string{jerr.Error()},
				}
				c.AbortWithStatusJSON(err.Code, err)
				return true
			}
			if req.Body != nil {
				req.Body.Close()
			}
			req.Body = ioutil.NopCloser(bytes.NewReader([]byte(jstr)))
			req.ContentLength = int64(len([]byte(jstr)))
		}

		// Remove Writer Headers - let the caller put them in.
		c.Writer.Header().Del("Access-Control-Allow-Credentials")
		c.Writer.Header().Del("Access-Control-Expose-Headers")
		c.Writer.Header().Del("Access-Control-Allow-Origin")

		if gzw, ok := c.Writer.(*gzip.GzipWriter); ok {
			gzw.SetSkipCompression(c)
		}

		// Note that ServeHttp is non blocking and uses a go routine under the hood
		proxy.ServeHTTP(c.Writer, req)
		return true
	}
	return false
}

//
// This returns two bools.  If either is true, the call should just return.
// First bool is forwarded or not.
// Second bool is true if the object is not yours and an error was returned.
//
func (fe *Frontend) processRequestWithForwarding(c *gin.Context, obj interface{}, newBody interface{}) (bool, bool) {
	// Should we proxy this - manager plugin sends with true.
	if v, ok := c.GetQuery("noproxy"); ok && v == "true" {
		return false, false
	}
	mobj, _ := obj.(models.Model)
	if owned, ook := mobj.(models.Owner); ook {
		owner := owned.GetEndpoint()
		if owner == "" {
			return false, false // This is mine, don't forward.
		}
		for _, id := range fe.DrpIds {
			if owner == id {
				return false, false // This is mine, don't forward.
			}
		}
		if fok := fe.forwardRequest(c, owned.GetEndpoint(), "", newBody); fok {
			return true, true // forwarded and not mine
		}
		err := &models.Error{
			Model:    mobj.Prefix(),
			Key:      mobj.Key(),
			Code:     http.StatusNotFound,
			Type:     c.Request.Method,
			Messages: []string{"Not Found"},
		}
		c.AbortWithStatusJSON(err.Code, err)
		return false, true // This is not forward, but is also not mine.
	}
	return false, false // Not forwarded and mine (likely)
}
