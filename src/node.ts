/**
 * Run the proxy under Node: `node --env-file-if-exists=.env src/node.ts`.
 *
 * Node's http server speaks IncomingMessage, not `Request`, so this adapts one
 * to the other and back. Everything that matters lives in `proxy.ts`.
 */
import { createServer, type Server } from 'node:http';
import { Readable } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import type { ReadableStream as WebReadableStream } from 'node:stream/web';
import { fileURLToPath } from 'node:url';

import { configFromEnv, consoleLog, createProxy, type Log } from './proxy.ts';

export function listen(handle: (request: Request) => Promise<Response>, port: number, log: Log = consoleLog): Server {
    return createServer(async (req, res) => {
        try {
            const headers = new Headers();
            for (let i = 0; i < req.rawHeaders.length; i += 2) headers.append(req.rawHeaders[i]!, req.rawHeaders[i + 1]!);
            const hasBody = req.method !== 'GET' && req.method !== 'HEAD';
            // The host is irrelevant: the proxy routes on path alone, and its
            // public identity comes from PUBLIC_URL, never from a request header.
            const request = new Request(new URL(req.url ?? '/', 'http://localhost'), {
                method: req.method,
                headers,
                ...(hasBody ? { body: Readable.toWeb(req) as ReadableStream, duplex: 'half' } : {})
            });

            const response = await handle(request);
            res.writeHead(response.status, Object.fromEntries(response.headers));
            if (!response.body) return void res.end();
            // `pipeline` tears both ends down if either fails, so a client that
            // hangs up cancels the upstream read too.
            await pipeline(Readable.fromWeb(response.body as WebReadableStream), res);
        } catch (error) {
            log('error', 'request failed', { error: error instanceof Error ? error.message : String(error) });
            if (!res.headersSent) res.writeHead(500).end();
            else res.destroy();
        }
    }).listen(port);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    const config = configFromEnv(process.env);
    const port = Number(process.env.PORT ?? 8080);
    listen(createProxy(config), port);
    consoleLog('info', 'proxy listening', {
        port,
        resource: config.publicUrl.href,
        upstream: config.upstreamUrl.href,
        issuer: config.issuer,
        // Printed beside the resource because they often differ, and that looks
        // like a bug for ten minutes. Keycloak ignores RFC 8707 `resource`, so
        // `aud` is whatever the realm's mapper emits; align this with the realm.
        audience: config.audience ?? '(not checked)'
    });
}
