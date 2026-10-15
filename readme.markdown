Fleck
===

[![Build status](https://ci.appveyor.com/api/projects/status/k0s8hq5y4emak5j3/branch/master?svg=true)](https://ci.appveyor.com/project/statianzo/fleck/branch/master) [![NuGet](https://img.shields.io/nuget/v/Fleck.svg)](https://www.nuget.org/packages/Fleck/)

Fleck is a WebSocket server implementation in C#. Branched from the
[Nugget][nugget] project, Fleck requires no inheritance, container, or
additional references.

Example
---

The following is an example that will echo to a client.

```c#

var server = new WebSocketServer("ws://0.0.0.0:8181");
server.Start(socket =>
{
  socket.OnOpen = () => Console.WriteLine("Open!");
  socket.OnClose = () => Console.WriteLine("Close!");
  socket.OnMessage = message => socket.Send(message);
});
        
```

Supported WebSocket Versions
---

Fleck supports several WebSocket versions of modern web browsers

- Hixie-Draft-76/Hybi-00 (Safari 5, Chrome < 14, Firefox 4 (when enabled))
- Hybi-07 (Firefox 6)
- Hybi-10 (Chrome 14-16, Firefox 7)
- Hybi-13 (Chrome 17+, Firefox 11+, Safari 6+, Edge 13+(?))

Secure WebSockets (wss://)
---

Enabling secure connections requires two things: using the scheme `wss` instead
of `ws`, and pointing Fleck to an x509 certificate containing a public and
private key

```cs
var server = new WebSocketServer("wss://0.0.0.0:8431");
server.Certificate = new X509Certificate2("MyCert.pfx");
server.Start(socket =>
{
  //...use as normal
});
```

Having issues making a certificate? See this
[guide to creating an x509](https://github.com/statianzo/Fleck/issues/214#issuecomment-364413879)
by [@AdrianBathurst](https://github.com/AdrianBathurst)

SubProtocol Negotiation
---

To enable negotiation of subprotocols, specify the supported protocols on
the `WebSocketServer.SupportedSubProtocols` property. The negotiated
subprotocol will be available on the socket's `ConnectionInfo.NegotiatedSubProtocol`.

If no supported subprotocols are found on the client request (the
Sec-WebSocket-Protocol header), the connection will be closed.

```cs
var server = new WebSocketServer("ws://0.0.0.0:8181");
server.SupportedSubProtocols = new []{ "superchat", "chat" };
server.Start(socket =>
{
  //socket.ConnectionInfo.NegotiatedSubProtocol is populated
});
```

Custom Logging
---

Fleck can log into Log4Net or any other third party logging system. Just override the `FleckLog.LogAction` property with the desired behavior.

```cs
ILog logger = LogManager.GetLogger(typeof(FleckLog));

FleckLog.LogAction = (level, message, ex) => {
  switch(level) {
    case LogLevel.Debug:
      logger.Debug(message, ex);
      break;
    case LogLevel.Error:
      logger.Error(message, ex);
      break;
    case LogLevel.Warn:
      logger.Warn(message, ex);
      break;
    default:
      logger.Info(message, ex);
      break;
  }
};

```

Disable Nagle's Algorithm
---

Set `NoDelay` to `true` on the `WebSocketConnection.ListenerSocket`

```cs
var server = new WebSocketServer("ws://0.0.0.0:8181");
server.ListenerSocket.NoDelay = true;
server.Start(socket =>
{
  //Child connections will not use Nagle's Algorithm
});
```

Auto Restart After Listen Error
---

If the listener socket fails, the server recreates it with a backoff of up to 30 seconds between attempts.
This is on by default, set `RestartAfterListenError` to `false` on the `WebSocketServer` to disable it.

```cs
var server = new WebSocketServer("ws://0.0.0.0:8181");
server.RestartAfterListenError = false;
server.Start(socket =>
{
  //...use as normal
});
```

Logging Level
---

`FleckLog.Level` is the minimum level passed to `LogAction`. For example, `LogLevel.Warn` passes warnings and errors.
`Debug` and `Info` messages are only logged by debug builds of Fleck.

```cs
FleckLog.Level = LogLevel.Error;
FleckLog.LogAction = (level, message, ex) => Console.Error.WriteLine($"[Fleck] {message} {ex}");
```

Message Size Limit
---

`MaxMessageSize` on the `WebSocketServer` limits how big a message (all of its fragments together) a connection can
receive, 1 MB by default. Positive values below 1024 bytes are clamped to 1024. Bigger messages close the connection
with 1009 (message too big). Each connection's receive buffers start at 64 KB and only grow when a message needs them to.

```cs
var server = new WebSocketServer("ws://0.0.0.0:8181");
server.MaxMessageSize = 64 * 1024;
```

Connection Limits
---

The server's `Limiter` refuses connections beyond a total (500) and per IP address (5), and limits how many connection
attempts each IP can make in a window (5 every 5 seconds). These can be passed to the `WebSocketServer` constructor or
changed on the limiter, with -1 turning a limit off.

```cs
var server = new WebSocketServer("ws://0.0.0.0:8181", maxConnections: 1000, maxConnectionsPerIP: 10);
server.Limiter.SetAttemptLimits(maxAttemptsPerWindow: 20, attemptWindow: TimeSpan.FromSeconds(10));
```

Clients have `HandshakeTimeout` (10 seconds by default) to complete their handshake, including TLS, or they're
disconnected. This stops clients that connect and never finish the handshake from holding connection slots. Zero or
less, or anything too long to schedule (about 49 days or more, e.g. `TimeSpan.MaxValue`), turns it off.

```cs
server.HandshakeTimeout = TimeSpan.FromSeconds(5);
```

Pings
---

Pings from clients are passed to `OnPing` but aren't answered automatically. Clients that ping to check the connection
is alive expect a pong with the same payload.

Echoing the payload is safe because it's always small. Large pings are never answered: the protocol limits ping
payloads to 125 bytes, and Fleck closes the connection (1002, protocol error) for a bigger ping before `OnPing` is
called. So a pong never carries more than 125 bytes:

```cs
socket.OnPing = data =>
{
  var pong = new MemoryBuffer(data.Length).Slice(data.Length);
  data.CopyTo(pong.Data);
  socket.SendPong(pong);
};
```

A client that floods pings still gets a pong for each one. If it sends them faster than it reads the pongs, it's
disconnected like any other client that stops reading (see Sending and Closing).

Sending and Closing
---

Sends never block: each connection queues them and writes them in order, one at a time. A connection with more than
2048 sends waiting (e.g. a client that stopped reading) is disconnected. Sending to a closed connection is ignored.
Sending from the `Start` callback throws, because the handshake response hasn't been queued yet: send from `OnOpen`
instead. Once the handshake response is queued, sends are accepted even before `OnOpen` runs, and go out after it.

`Close()` closes normally (1000), `Close(code)` closes with a status code. When a client closes the connection, Fleck
answers with the client's status code and then raises `OnClose`.

`OnOpen` is always raised before any `OnMessage`, `OnBinary`, `OnPing` or `OnPong`.

Exceptions thrown by handlers:

- `OnMessage`, `OnBinary`, `OnPing` and `OnPong`: passed to `OnError`, logged as an error, and the connection is
  closed with 1011 (internal error). Catch them in the handler if a bad message shouldn't disconnect the client.
- `OnOpen`: passed to `OnError`, the connection stays open.
- `OnClose` and `OnError`: logged as an error, the connection is still cleaned up.
- `LogAction`: ignored, so a broken logger can't stop connections being cleaned up.

[nugget]: http://nugget.codeplex.com/ 
