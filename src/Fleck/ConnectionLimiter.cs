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

        public bool TryAdd(IPAddress address)
        {
            if (address == null)
            {
                return false;
            }

            lock (_sync)
            {
                if (_maxConnections != -1 && _overallCount >= _maxConnections)
                {
                    return false;
                }

                if (!_clients.TryGetValue(address, out var state))
                {
                    state = new ClientState
                    {
                        ActiveConnections = 0,
                        AttemptCount = 0,
                        WindowStart = DateTime.UtcNow
                    };

                    _clients[address] = state;
                }

                var now = DateTime.UtcNow;

                if (now - state.WindowStart > _attemptWindow)
                {
                    state.WindowStart = now;
                    state.AttemptCount = 0;
                }
                else
                {
                    state.WindowStart = now;
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
                state.AttemptCount++;
                state.ActiveConnections++;
                _overallCount++;

                return true;
            }
        }

        public void Remove(IPAddress address)
        {
            if (address == null)
            {
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

                if (state.ActiveConnections == 0 && state.AttemptCount == 0)
                {
                    _clients.Remove(address);
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