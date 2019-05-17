package backend

import (
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/digitalrebar/logger"
)

// FileSystem provides the routines to allow the static HTTP and TFTP services to render
// templates on demand..
type FileSystem struct {
	sync.Mutex
	lower        string
	logger       logger.Logger
	dynamicFiles map[string]func(net.IP) (io.Reader, error)
	dynamicTrees map[string]func(string) (io.Reader, error)
}

// NewFS creates a new initialized filesystem that will fall back to
// serving files from backingFSPath if there is not a template to be
// rendered.
func NewFS(backingFSPath string, logger logger.Logger) *FileSystem {
	return &FileSystem{
		lower:        backingFSPath,
		logger:       logger,
		dynamicFiles: map[string]func(net.IP) (io.Reader, error){},
		dynamicTrees: map[string]func(string) (io.Reader, error){},
	}
}

func (fs *FileSystem) findTree(p string) func(string) (io.Reader, error) {
	if len(fs.dynamicTrees) == 0 {
		return nil
	}
	for {
		if r, ok := fs.dynamicTrees[p]; ok {
			return r
		}
		if p == "" || p == "/" {
			break
		}
		p = path.Dir(p)
	}
	return nil
}

// Open tests for the existence of a lookaside for file read request.
// The returned Reader amd error contains the results of running the
// lookaside function if one is present. If both the reader and error
// are nil, FileSystem should fall back to serving a static file.
func (fs *FileSystem) Open(p string, remoteIP net.IP) (io.Reader, error) {
	p = path.Clean(p)
	fs.Lock()
	dynFile := fs.dynamicFiles[p]
	dynTree := fs.findTree(p)
	fs.Unlock()
	if dynFile != nil {
		return dynFile(remoteIP)
	}
	if dynTree != nil {
		return dynTree(p)
	}
	return nil, nil
}

// ServeHTTP implements http.Handler for the FileSystem.
func (fs *FileSystem) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if !strings.HasPrefix(p, "/") {
		p = path.Clean("/" + p)
		r.URL.Path = p
	}
	r.Body.Close()
	var raddr net.IP
	raddrStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		fs.logger.Errorf("Static FS: Failed to resolve %s: %v", r.RemoteAddr, err)
	} else {
		raddr = net.ParseIP(raddrStr)
	}
	out, err := fs.Open(p, raddr)
	if err != nil {
		fs.logger.Errorf("Static FS: Dynamic file error for %s: %v", p, err)
		w.WriteHeader(http.StatusInternalServerError)
	} else if out != nil {
		if sz, ok := out.(Sizer); ok {
			w.Header().Set("Content-Length", strconv.FormatInt(sz.Size(), 10))
		}
		io.Copy(w, out)
		if cl, ok := out.(io.ReadCloser); ok {
			cl.Close()
		}
	} else {
		http.ServeFile(w, r, path.Join(fs.lower, p))
	}
}

// TftpResponder returns a function that allows the TFTP midlayer to
// serve files from the FileSystem.
func (fs *FileSystem) TftpResponder() func(string, net.IP) (io.Reader, error) {
	return func(toSend string, remoteIP net.IP) (io.Reader, error) {
		p := path.Clean("/" + toSend)
		out, err := fs.Open(p, remoteIP)
		if err != nil {
			fs.logger.Errorf("Static FS: Dynamic file error for %s: %v", p, err)
			return nil, err
		}
		if out != nil {
			return out, nil
		}
		return os.Open(path.Join(fs.lower, p))
	}
}

func (fs *FileSystem) addDynamicFile(fsPath string, t func(net.IP) (io.Reader, error)) {
	fs.dynamicFiles[fsPath] = t
}

func (fs *FileSystem) delDynamicFile(fsPath string) {
	delete(fs.dynamicFiles, fsPath)
}

// AddDynamicFile adds a lookaside that handles rendering a file that should be generated on
// the fly.  fsPath is the path where the dynamic lookaside lives, and the passed-in function
// will be called with the IP address of the system making the request.
func (fs *FileSystem) AddDynamicFile(fsPath string, t func(net.IP) (io.Reader, error)) {
	fs.Lock()
	fs.dynamicFiles[fsPath] = t
	fs.Unlock()
}

// DelDynamicFile removes a lookaside registered for fsPath, if any.
func (fs *FileSystem) DelDynamicFile(fsPath string) {
	fs.Lock()
	delete(fs.dynamicFiles, fsPath)
	fs.Unlock()
}

// AddDynamicTree adds a lookaside responsible for wholesale
// impersonation of a directory tree.  fsPath indicates where
// AddDynamicTree will start handling all read requests, and the
// passed-in function will be called with the full path to whatever
// was being requested.
func (fs *FileSystem) AddDynamicTree(fsPath string, t func(string) (io.Reader, error)) {
	fs.Lock()
	fs.dynamicTrees[path.Join("/", fsPath)] = t
	fs.Unlock()
}

// DelDynamicTree removes a lookaside responsible for wholesale
// impersonation of a directory tree.
func (fs *FileSystem) DelDynamicTree(fsPath string) {
	fs.Lock()
	delete(fs.dynamicTrees, path.Join("/", fsPath))
	fs.Unlock()
}
