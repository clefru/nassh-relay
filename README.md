nassh-relay
===========

Relay for Native Client SSH, see http://goo.gl/HMsm8p

Typical use case is when you want to firewall your sshd port. Also the
relay supports roaming clients better than a direct TCP connection, as
the TCP stack cuts the connection if the client IP changes. This relay
on the other hand supports reconnecing from all HTTP client as long as
the client can present it with the correct session ID[*].

Invoke:
$ node nassh-relay.js <port> [external-redirect]

At relay selection, the server echos back the HTTP Host header as the
relay. If that host is not directly reachable by its clients, you need
to specify an external-redirect.

[*] The session is still protected by SSH, so guessing the session ID
is a denial of service attack and allows sniffing the encrypted sshd
response bytestream.
