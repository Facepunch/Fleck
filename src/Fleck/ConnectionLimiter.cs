using System;
using System.Collections.Generic;
using System.Net;

namespace Fleck
{
    // largely based on the connection limiter written for the companion server
    public class ConnectionLimiter
    {
        private readonly object _sync = new object();

        private readonly Dictionary<IPAddress, ClientState> _clients = new Dictionary<IPAddress, ClientState>();

        private int _overallCount;

        private int _maxConnectionsPerIP = 5;
        private int _maxConnections = 500;

        private int _maxAttemptsPerWindow = 5;
        private TimeSpan _attemptWindow = TimeSpan.FromSeconds(5);

        // how often idle entries are swept out, so IPs that never come back (e.g. scanners) don't accumulate forever
        private static readonly TimeSpan PruneInterval = TimeSpan.FromMinutes(1);
        private DateTime _lastPrune = DateTime.UtcNow;

        private class ClientState
        {
            public int ActiveConnections;
            public int AttemptCount;
            public DateTime WindowStart;
        }

        public void SetConnectionLimits(int maxConnections, int maxConnectionsPerIP)
        {
            _maxConnections = maxConnections;
            _maxConnectionsPerIP = maxConnectionsPerIP;
        }

        /// <summary>
        /// Limits how many connection attempts each IP can make within a window. -1 disables the limit.
        /// </summary>
        public void SetAttemptLimits(int maxAttemptsPerWindow, TimeSpan attemptWindow)
        {
            lock (_sync)
            {
                _maxAttemptsPerWindow = maxAttemptsPerWindow;
                _attemptWindow = attemptWindow;
            }
        }

        public bool TryAdd(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }

            lock (_sync)
            {
                var now = DateTime.UtcNow;

                if (now - _lastPrune > PruneInterval)
                {
                    Prune(now);
                }

                if (_maxConnections != -1 && _overallCount >= _maxConnections)
                {
                    return false;
                }

                // the first attempt in a window counts as 0, so _maxAttemptsPerWindow attempts are allowed in each window,
                // whether this IP is new or its previous window has passed
                if (!_clients.TryGetValue(address, out var state))
                {
                    state = new ClientState
                    {
                        ActiveConnections = 0,
                        AttemptCount = 0,
                        WindowStart = now
                    };

                    _clients[address] = state;
                }
                else if (now - state.WindowStart > _attemptWindow)
                {
                    state.WindowStart = now;
                    state.AttemptCount = 0;
                }
                else
                {
                    state.AttemptCount++;
                }

                if (_maxAttemptsPerWindow != -1 && state.AttemptCount >= _maxAttemptsPerWindow)
                {
                    return false;
                }

                if (_maxConnectionsPerIP != -1 && state.ActiveConnections >= _maxConnectionsPerIP)
                {
                    return false;
                }

                // no need to reject yet, increment
                state.ActiveConnections++;
                _overallCount++;

                return true;
            }
        }

        public void Remove(IPAddress address)
        {
            if (address == null)
            {
                // likely an edge case we'll never hit but if we ever end up in a case where both the socket/connectioninfo have null ips
                // we still want to decrement our total active connections to prevent exhausting our connection limits
                Remove();
                return;
            }

            lock (_sync)
            {
                if (!_clients.TryGetValue(address, out var state))
                {
                    return;
                }

                if (state.ActiveConnections > 0)
                {
                    state.ActiveConnections--;
                    _overallCount--;
                }

                if (IsIdle(state, DateTime.UtcNow))
                {
                    _clients.Remove(address);
                }
            }
        }

        public void Remove()
        {
            lock (_sync)
            {
                _overallCount--;
            }
        }

        // nothing to remember once there are no connections and the attempt window has passed, since the next attempt
        // would start a fresh window anyway. the entry has to be kept until then even with no connections, or connecting
        // and disconnecting in a loop would never be limited
        private bool IsIdle(ClientState state, DateTime now)
        {
            return state.ActiveConnections == 0 && now - state.WindowStart > _attemptWindow;
        }

        internal void Prune(DateTime now)
        {
            lock (_sync)
            {
                _lastPrune = now;

                List<IPAddress> idle = null;
                foreach (var pair in _clients)
                {
                    if (IsIdle(pair.Value, now))
                    {
                        (idle ?? (idle = new List<IPAddress>())).Add(pair.Key);
                    }
                }

                if (idle == null)
                {
                    return;
                }

                foreach (var address in idle)
                {
                    _clients.Remove(address);
                }
            }
        }

        internal int TrackedClientCount
        {
            get
            {
                lock (_sync)
                {
                    return _clients.Count;
                }
            }
        }

        public void Clear()
        {
            lock (_sync)
            {
                _clients.Clear();
                _overallCount = 0;
            }
        }
    }
}