using Fleck.Handlers;

namespace Fleck
{
    public class HandlerFactory
    {
        public static IHandler BuildHandler(WebSocketHttpRequest request, IWebSocketConnection connection, int maxMessageSize = WebSocketServer.DefaultMaxMessageSize)
        {
            var version = GetVersion(request);
            
            switch (version)
            {
                case "7":
                case "8":
                case "13":
                    return new Hybi13Handler(request, connection, maxMessageSize);
            }
            
            throw new WebSocketException(WebSocketStatusCodes.ProtocolError);
        }
        
        public static string GetVersion(WebSocketHttpRequest request) 
        {
            string version;
            if (request.Headers.TryGetValue("Sec-WebSocket-Version", out version))
                return version;
                
            if (request.Headers.TryGetValue("Sec-WebSocket-Draft", out version))
                return version;
            
            if (request.Headers.ContainsKey("Sec-WebSocket-Key1"))
                return "76";

            return "75";
        }
    }
}

