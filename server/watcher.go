package server

import (
	"fmt"
	"os"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"github.com/kardianos/osext"
)

// watchSelf watches for changes in the main binary and hot-swaps itself for the newly
// built binary file
func watchSelf() (chan struct{}, error) {

	// Retrieve file info for the currently running program
	file, err := osext.Executable()
	if err != nil {
		return nil, err
	}

	// Initialize and prepare a new file watcher
	fmt.Printf("watching %q\n", file)
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		for {
			select {
			case e := <-w.Events:
				// Events mean changes
				fmt.Printf("watcher received: %+v", e)

				// Replace the running system call with a new call
				// to our newly combined binary
				err := syscall.Exec(file, os.Args, os.Environ())
				if err != nil {
					fmt.Errorf("%#v", err)
				}

			case err := <-w.Errors:
				// Print out errors as they occur
				fmt.Printf("watcher error: %+v", err)

			case <-done:
				// If we ever close the watcher, log it
				fmt.Printf("watcher shutting down")
				return
			}
		}
	}()

	// Add our running file to be watched
	err = w.Add(file)
	if err != nil {
		return nil, err
	}
	return done, nil
}
