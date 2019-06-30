drpcli interfaces
-----------------

Access CLI commands relating to interfaces

Synopsis
~~~~~~~~

Access CLI commands relating to interfaces

Options
~~~~~~~

::

     -h, --help   help for interfaces

Options inherited from parent commands
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

     -c, --catalog string      The catalog file to use to get product information (default "https://repo.rackn.io")
     -d, --debug               Whether the CLI should run in debug mode
     -E, --endpoint string     The Digital Rebar Provision API endpoint to talk to (default "https://127.0.0.1:8092")
     -f, --force               When needed, attempt to force the operation - used on some update/patch calls
     -F, --format string       The serialzation we expect for output.  Can be "json" or "yaml" (default "json")
     -x, --noToken             Do not use token auth or token cache
     -P, --password string     password of the Digital Rebar Provision user (default "r0cketsk8ts")
     -r, --ref string          A reference object for update commands that can be a file name, yaml, or json blob
     -T, --token string        token of the Digital Rebar Provision access
     -t, --trace string        The log level API requests should be logged at on the server side
     -Z, --traceToken string   A token that individual traced requests should report in the server logs
     -U, --username string     Name of the Digital Rebar Provision user to talk to (default "rocketskates")

SEE ALSO
~~~~~~~~

-  `drpcli <drpcli.html>`__ - A CLI application for interacting with the
   DigitalRebar Provision API
-  `drpcli interfaces exists <drpcli_interfaces_exists.html>`__ - See if
   a interfaces exists by id
-  `drpcli interfaces indexes <drpcli_interfaces_indexes.html>`__ - Get
   indexes for interfaces
-  `drpcli interfaces list <drpcli_interfaces_list.html>`__ - List all
   interfaces
-  `drpcli interfaces show <drpcli_interfaces_show.html>`__ - Show a
   single interfaces by id
-  `drpcli interfaces wait <drpcli_interfaces_wait.html>`__ - Wait for a
   interface’s field to become a value within a number of seconds
