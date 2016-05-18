SSHHiPot
=========
High-interaction SSH honeypot (ok, it's really a logging ssh proxy).

Still very much a work-in-progress.  Feel free to `go install` this repository
if you'd like to try it.  Run it with `-h` to see more options.

One of these days there'll be better documentation, really.

The general idea is that sshlowpot runs somewhere between the attacker and the
real SSH server such that the attacker logs into the honeypot, and the honeypot
logs into the server.

Config
------
Most of the options should be useable as-is.  The ones I expect will need to
be configured:
Option | Use
-------|----
`-ck`  | SSH identity file (i.e. `id_rsa`) to use to authenticate to the server.
`-cs`  | Server's address.  Can be loopback, even.
`-cu`  | Ok, maybe `root` wasn't a great default.  `test` is probably better.
`-p`   | Try `123456` or something more common than [`hunter2`](http://bash.org/?244321).

Please note by default the server listens on port 2222.  You'll have to use
pf or iptables or whatever other firewall to redirect the port.

Windows
-------
It's in Go, so, probably?  Send me a pull request if it doesn't work.
