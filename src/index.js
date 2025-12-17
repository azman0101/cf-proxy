import { connect } from 'cloudflare:sockets';

// CONFIGURATION
const PROXY_USERNAME = "monUser";
const ALLOWED_TLS_VERSION = "TLSv1.3";

export default {
  async fetch(request, env, ctx) {
    // 1. TLS 1.3 Check (Enforcement)
    // Cloudflare handles ECH (Encrypted Client Hello) termination.
    // Enforcing TLS 1.3 is key to ensuring ECH compatibility and security.
    const clientTlsVersion = request.cf?.tlsVersion;
    if (clientTlsVersion !== ALLOWED_TLS_VERSION) {
      return new Response(`Insufficient Security: ${clientTlsVersion} detected. TLS 1.3 required.`, { status: 400 });
    }

    // 2. Authentication (Basic Auth)
    const authHeader = request.headers.get("Proxy-Authorization");

    // Use environment variables if set, otherwise fallback to defaults
    const username = env.PROXY_USERNAME || PROXY_USERNAME;

    // Retrieve password from KV
    let password = null;
    if (env.PROXY_CONFIG) {
        password = await env.PROXY_CONFIG.get("PROXY_PASSWORD");
    }

    if (!password) {
        // Fallback or error if KV is not configured or key is missing
        // For safety, we can return 500 or just fail auth.
        // Let's assume there is a fallback env var if KV fails or is empty,
        // or just fail. Given the request is to REPLACE, we should rely on KV.
        // However, user might have env var as well.
        // Let's check env.PROXY_PASSWORD as a backup or initial value if KV is missing?
        // "Remplacer const PROXY_PASSWORD par un binding kv" -> Remove const.
        password = env.PROXY_PASSWORD || "defaultPasswordChangeMe";
    }

    const expectedAuth = "Basic " + btoa(`${username}:${password}`);

    if (!authHeader || authHeader !== expectedAuth) {
      return new Response("Authentication Required", {
        status: 407,
        headers: { "Proxy-Authenticate": "Basic realm='Secure Proxy'" }
      });
    }

    // 3. Handle CONNECT Method (HTTPS Tunneling)
    if (request.method === "CONNECT") {
      return handleConnect(request, ctx);
    }

    // 4. Handle Standard HTTP Requests
    return handleHttp(request);
  },
};

// Handles TCP tunnel creation for CONNECT requests
async function handleConnect(request, ctx) {
  let hostname, port;

  // Robustly parse the target URL.
  // In some environments, request.url is a full URL, in others it might be host:port.
  try {
    const url = new URL(request.url);
    hostname = url.hostname;
    port = parseInt(url.port) || 443;
  } catch (e) {
    try {
        // Fallback: try prepending https:// if it looks like host:port
        const url = new URL(`https://${request.url}`);
        hostname = url.hostname;
        port = parseInt(url.port) || 443;
    } catch (e2) {
        return new Response("Invalid Request URL", { status: 400 });
    }
  }

  try {
    // Create outbound TCP socket to the target
    const socket = connect({ hostname, port });

    // Accept the client connection using WebSocketPair
    // This allows us to bridge the raw TCP of the client to our worker logic.
    // Cloudflare Workers runtime treats 'webSocket' in response to CONNECT as a tunnel acceptance.
    const { 0: client, 1: server } = new WebSocketPair();
    server.accept();

    // Pipe data between client (server WebSocket) and target (socket)
    ctx.waitUntil(pipeSocketToClient(socket, server));

    // Return 200 OK with the client WebSocket to establish the tunnel
    return new Response(null, { status: 200, webSocket: client });

  } catch (err) {
    return new Response(`Connection to target failed: ${err.message}`, { status: 502 });
  }
}

// Pipes data between the TCP socket and the WebSocket (representing client)
async function pipeSocketToClient(socket, server) {
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();

  // Stream: Client (WebSocket) -> Target (TCP Socket)
  server.addEventListener('message', async (event) => {
    try {
        // WebSocket messages can be string or ArrayBuffer.
        if (event.data instanceof ArrayBuffer) {
            await writer.write(new Uint8Array(event.data));
        } else if (typeof event.data === 'string') {
            await writer.write(new TextEncoder().encode(event.data));
        } else {
            // Handle other types if necessary
            console.warn("Unknown data type from client");
        }
    } catch (err) {
        // If writing to target fails, close the client side
        server.close();
    }
  });

  server.addEventListener('close', () => {
      // Client closed connection
      try { writer.close(); } catch(e){}
  });

  // Stream: Target (TCP Socket) -> Client (WebSocket)
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      // server.send handles ArrayBuffer/TypedArray/String
      server.send(value);
    }
  } catch (err) {
    console.error("Error reading from target:", err);
  } finally {
    // Target closed connection or error occurred
    server.close();
  }
}

async function handleHttp(request) {
  // Proxy simple HTTP requests
  const newRequest = new Request(request.url, {
      method: request.method,
      headers: new Headers(request.headers),
      body: request.body,
      redirect: 'manual'
  });

  // Remove Proxy headers
  newRequest.headers.delete("Proxy-Authorization");

  return fetch(newRequest);
}
