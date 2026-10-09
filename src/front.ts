/**
 * An OAuth discovery front for an Agent Gateway route.
 *
 * An MCP client pointed straight at an Affinidi Agent Gateway access point
 * cannot sign in: the Gateway answers with a spec-shaped 401, but the discovery
 * documents that challenge points at serve the dashboard's HTML, so the client
 * follows the pointer, receives a web page, and stops.
 *
 * This front stands in for that missing half. It owns a public URL, publishes
 * RFC 9728 protected-resource metadata naming your IdP, answers a real 401
 * challenge, and forwards each request carrying a bearer token to the Gateway
 * route. The Gateway does everything else: it verifies the token, applies its
 * trust policy, injects the credential the resource needs, and audits the call.
 *
 * It does not verify tokens. The check below decodes the token without
 * checking its signature, so anyone can forge one that passes. That is fine
 * only because the access point verifies it properly, and the README says so.
 * The check exists to tell an expired or foreign token (answer 401, so the
 * client signs in again) from a Gateway that rejects a good-looking one (answer
 * a terminal 502, so the client does not loop through sign-in forever).
 *
 * A workaround, to be retired once an Agent Surface supports MCP's
 * Authorization Server Discovery itself:
 * https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery
 *
 * Written as a web-standard `fetch(Request) → Response` handler, so the same
 * file runs under Node (`node.ts`) and on any fetch-native runtime.
 */

export type Log = (level: 'info' | 'warn' | 'error', message: string, fields?: Record<string, unknown>) => void;

export const consoleLog: Log = (level, message, fields) =>
    console[level](JSON.stringify({ time: new Date().toISOString(), level, message, ...fields }));

type Env = Record<string, string | undefined>;

/** An https URL, or http on localhost so the whole thing can run on one laptop. */
function secureUrl(env: Env, name: string): URL {
    const raw = env[name]?.trim();
    if (!raw) throw new Error(`${name} is required`);
    let url: URL;
    try {
        url = new URL(raw);
    } catch {
        throw new Error(`${name} is not a URL: ${raw}`);
    }
    const local = url.hostname === 'localhost' || url.hostname === '127.0.0.1';
    if (url.protocol !== 'https:' && !local) throw new Error(`${name} must be https (or localhost for development): ${raw}`);
    return url;
}

export function configFromEnv(env: Env) {
    const publicUrl = secureUrl(env, 'PUBLIC_URL');
    const upstreamUrl = secureUrl(env, 'UPSTREAM_URL');
    // Do not normalise the issuer's trailing slash. Keycloak's has none, other
    // providers' (Auth0's) genuinely do, and `iss` is compared as an exact string.
    secureUrl(env, 'OIDC_ISSUER');
    const issuer = env.OIDC_ISSUER!.trim();

    // The arrangement can be circular by design (out to the Gateway and back to
    // a resource on the same host), so a route aimed at this front itself loops
    // until something runs out of sockets. Cheaper to refuse to start.
    const strip = (url: URL) => url.origin + url.pathname.replace(/\/$/, '');
    if (strip(upstreamUrl) === strip(publicUrl)) {
        throw new Error(`UPSTREAM_URL points back at this front (${publicUrl.href}). It must name the Agent Gateway route.`);
    }

    const upstreamTimeoutMs = Number(env.UPSTREAM_TIMEOUT_MS ?? 30_000);
    if (!(upstreamTimeoutMs > 0)) throw new Error(`UPSTREAM_TIMEOUT_MS must be a positive number: ${env.UPSTREAM_TIMEOUT_MS}`);

    return {
        /** This front's public URL. It is the OAuth resource identifier, and its path is where MCP requests arrive. */
        publicUrl,
        /** The Agent Gateway access-point route every admitted request is forwarded to. */
        upstreamUrl,
        /** Compared to the token's `iss` as an exact string, trailing slash and all. */
        issuer,
        /** If set, the token's `aud` must contain it. */
        audience: env.JWT_AUDIENCE?.trim() || undefined,
        scopes: (env.SCOPES ?? 'openid,email,offline_access').split(',').map(s => s.trim()).filter(Boolean),
        resourceName: env.RESOURCE_NAME?.trim() || 'MCP server',
        /** Also send the token in this header, for a resource behind the Gateway that wants to see the caller. */
        forwardTokenHeader: env.FORWARD_TOKEN_HEADER?.trim().toLowerCase() || undefined,
        // JSON only by default, because the Gateway's SSE response path sends
        // headers and then terminates without a body. It relays this Accept to
        // the resource, which should answer in JSON response mode. Overridable
        // because this is the header most likely to matter if the Gateway changes.
        upstreamAccept: env.UPSTREAM_ACCEPT?.trim() || 'application/json',
        upstreamTimeoutMs
    };
}

export type Config = ReturnType<typeof configFromEnv>;

/**
 * Where the RFC 9728 document lives: the well-known prefix inserted before the
 * resource's path. Also served at the bare prefix, since this front owns its
 * host and some clients only look there.
 */
export function resourceMetadataUrl(publicUrl: URL): string {
    const path = publicUrl.pathname === '/' ? '' : publicUrl.pathname;
    return `${publicUrl.origin}/.well-known/oauth-protected-resource${path}`;
}

/** Decode a JWT's claims without verifying anything. `undefined` if it is not a JWT. */
export function decodeClaims(token: string): Record<string, unknown> | undefined {
    const payload = token.split('.')[1];
    if (!payload) return undefined;
    try {
        const binary = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
        const claims: unknown = JSON.parse(new TextDecoder().decode(Uint8Array.from(binary, c => c.charCodeAt(0))));
        return claims && typeof claims === 'object' ? (claims as Record<string, unknown>) : undefined;
    } catch {
        return undefined;
    }
}

/** Why a token would be refused before reaching the Gateway, or `undefined` if it looks right. Not verification. */
export function precheck(claims: Record<string, unknown> | undefined, config: Config): string | undefined {
    if (!claims) return 'not a JWT';
    if (claims.iss !== config.issuer) return `issuer is ${String(claims.iss)}, expected ${config.issuer}`;
    if (typeof claims.exp !== 'number' || claims.exp * 1000 <= Date.now()) return 'expired';
    if (config.audience) {
        const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
        if (!aud.includes(config.audience)) return `audience is ${JSON.stringify(claims.aud)}, expected ${config.audience}`;
    }
    return undefined;
}

/** MCP headers worth carrying through. Everything else is ours to set, and hop-by-hop headers would be wrong on a new connection. */
const FORWARDED_REQUEST_HEADERS = ['mcp-protocol-version', 'mcp-session-id', 'last-event-id'];

/** Unauthenticated callers reach the body read, so it is capped. */
const MAX_BODY_BYTES = 1_000_000;

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });

function jsonRpcError(id: unknown, code: number, message: string, status: number): Response {
    return json({ jsonrpc: '2.0', error: { code, message }, id: id ?? null }, status);
}

async function readCapped(request: Request): Promise<string | undefined> {
    if (!request.body) return '';
    const chunks: Uint8Array<ArrayBuffer>[] = [];
    let size = 0;
    for await (const chunk of request.body) {
        size += chunk.byteLength;
        if (size > MAX_BODY_BYTES) return undefined;
        chunks.push(chunk);
    }
    return new Blob(chunks).text();
}

export interface FrontOptions {
    log?: Log;
    /** Injected in tests. */
    fetchImpl?: typeof fetch;
}

export function createFront(config: Config, { log = consoleLog, fetchImpl = fetch }: FrontOptions = {}) {
    const metadataUrl = resourceMetadataUrl(config.publicUrl);
    const metadataPaths = new Set([new URL(metadataUrl).pathname, '/.well-known/oauth-protected-resource']);
    const protectedResource = {
        resource: config.publicUrl.href,
        authorization_servers: [config.issuer],
        scopes_supported: config.scopes,
        resource_name: config.resourceName,
        bearer_methods_supported: ['header']
    };

    const challenge = (description?: string) =>
        json({ error: description ? 'invalid_token' : 'unauthorized', error_description: description ?? 'Sign-in required' }, 401, {
            'www-authenticate': description
                ? `Bearer error="invalid_token", error_description="${description.replace(/["\\]/g, '')}", resource_metadata="${metadataUrl}"`
                : `Bearer resource_metadata="${metadataUrl}"`
        });

    return async function handle(request: Request): Promise<Response> {
        const { pathname } = new URL(request.url);

        if (request.method === 'GET' && metadataPaths.has(pathname)) return json(protectedResource);

        if (pathname !== config.publicUrl.pathname) return json({ error: 'not found' }, 404);

        // Streamable HTTP lets a server decline the GET stream and session DELETE with a 405.
        if (request.method !== 'POST') return new Response(null, { status: 405, headers: { allow: 'POST' } });

        const token = request.headers.get('authorization')?.match(/^Bearer\s+(\S+)$/i)?.[1];
        if (!token) return challenge();
        const claims = decodeClaims(token);
        const refused = precheck(claims, config);
        if (refused) {
            // The client only reports "rejected", so this is the one place the
            // reason shows up. Claims only: the signature is not ours to log.
            log('warn', 'token refused', { reason: refused, claims: claims && { iss: claims.iss, aud: claims.aud, exp: claims.exp, sub: claims.sub } });
            return challenge(refused);
        }

        const body = await readCapped(request);
        if (body === undefined) return json({ error: 'request body too large' }, 413);
        let rpc: { id?: unknown; method?: unknown } = {};
        try {
            rpc = JSON.parse(body) ?? {};
        } catch {
            // Not ours to judge. The resource answers malformed JSON-RPC itself.
        }

        const headers: Record<string, string> = {
            'content-type': 'application/json',
            accept: config.upstreamAccept,
            authorization: `Bearer ${token}`
        };
        // The same token again, under a name nothing on the way competes for:
        // `Authorization` is the access point's to verify, consume or overwrite
        // with the credential it injects.
        if (config.forwardTokenHeader) headers[config.forwardTokenHeader] = token;
        for (const name of FORWARDED_REQUEST_HEADERS) {
            const value = request.headers.get(name);
            if (value) headers[name] = value;
        }

        const started = Date.now();
        let upstream: Response;
        try {
            upstream = await fetchImpl(config.upstreamUrl, {
                method: 'POST',
                headers,
                body,
                signal: AbortSignal.timeout(config.upstreamTimeoutMs)
            });
        } catch (error) {
            log('error', 'agent gateway unreachable', { error: error instanceof Error ? error.message : String(error) });
            return jsonRpcError(rpc.id, -32001, `The Agent Gateway in front of ${config.resourceName} did not respond.`, 502);
        }

        // A Gateway refusal of a token that passed the precheck is not
        // something the client can fix by signing in again: a 401 means the
        // access point does not accept this IdP's tokens, a 403 that its trust
        // policy denied the caller. Relaying either would be harmful, because a
        // client reads 401 as "authenticate again" and chases the Gateway's own
        // `WWW-Authenticate`, which points at HTML. Answer with something
        // terminal and put the detail where an operator will find it.
        if (upstream.status === 401 || upstream.status === 403) {
            const detail = await upstream.text().catch(() => '');
            log('error', 'agent gateway refused a request this front admitted', {
                status: upstream.status,
                detail: detail.slice(0, 500),
                sub: claims?.sub,
                hint:
                    upstream.status === 401
                        ? "The access point does not accept this IdP's tokens: check its JWT strategy and caller identity extraction."
                        : 'The access point trust policy denied the call.'
            });
            return jsonRpcError(
                rpc.id,
                -32002,
                `The Agent Gateway in front of ${config.resourceName} refused this request. Your sign-in worked; ` +
                    'this is a configuration fault, not something to retry.',
                502
            );
        }

        // Copied by name, not wholesale. Never relay the Gateway's `WWW-Authenticate`.
        const responseHeaders: Record<string, string> = {};
        for (const name of ['content-type', 'mcp-session-id']) {
            const value = upstream.headers.get(name);
            if (value) responseHeaders[name] = value;
        }
        const contentType = responseHeaders['content-type'];
        if (contentType?.includes('text/event-stream')) responseHeaders['cache-control'] = 'no-cache';

        log('info', 'forwarded', {
            method: rpc.method,
            status: upstream.status,
            // Negotiated against what we offered: the first thing to check when
            // a 200 arrives with nothing in it.
            upstreamContentType: contentType,
            ms: Date.now() - started,
            sub: claims?.sub
        });

        // ponytail: no DEBUG mode. If a 200 arrives with an empty body, the old
        // catalog-mcp gateway-front.ts buffered and logged the upstream body to tell
        // a slow call from one that never terminates; bring that back if needed.
        // Streamed, so a long tool call answering over SSE is not held until it finishes.
        return new Response(upstream.body, { status: upstream.status, headers: responseHeaders });
    };
}
