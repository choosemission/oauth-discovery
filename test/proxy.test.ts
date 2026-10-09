import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, describe, it } from 'node:test';

import { configFromEnv, createProxy, decodeClaims, precheck, resourceMetadataUrl } from '../src/proxy.ts';
import { listen } from '../src/node.ts';

const ISSUER = 'https://idp.example.com/realms/lab';
const UPSTREAM = 'https://train-soap.agentgateway.affinidi.io/routes/catalog/discover';
const ENV = {
    PUBLIC_URL: 'https://proxy.example.com/mcp',
    UPSTREAM_URL: UPSTREAM,
    OIDC_ISSUER: ISSUER,
    JWT_AUDIENCE: 'https://resource.example.com/mcp',
    RESOURCE_NAME: 'Test resource'
};
const CONFIG = configFromEnv(ENV);

/** Unsigned, which is the point: the proxy never looks at the signature. */
function token(claims: Record<string, unknown> = {}): string {
    const part = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
    const exp = Math.floor(Date.now() / 1000) + 300;
    return `${part({ alg: 'RS256' })}.${part({ iss: ISSUER, aud: ENV.JWT_AUDIENCE, exp, sub: 'user-1', ...claims })}.sig`;
}

const silent = () => {};
const reply = (body = '{"jsonrpc":"2.0","id":7,"result":{}}', init: ResponseInit = { headers: { 'content-type': 'application/json' } }) =>
    async () => new Response(body, init);

function proxy(fetchImpl: typeof fetch, config = CONFIG) {
    const handle = createProxy(config, { log: silent, fetchImpl });
    const call = (bearer: string | null = token(), body: unknown = { jsonrpc: '2.0', id: 7, method: 'tools/list' }) =>
        handle(
            new Request(config.publicUrl, {
                method: 'POST',
                headers: { 'content-type': 'application/json', ...(bearer ? { authorization: `Bearer ${bearer}` } : {}) },
                body: JSON.stringify(body)
            })
        );
    return { handle, call };
}

describe('configuration', () => {
    it('needs the three URLs', () => {
        assert.throws(() => configFromEnv({ ...ENV, UPSTREAM_URL: undefined }), /UPSTREAM_URL is required/);
    });

    it('refuses a plaintext upstream, since the token travels on it', () => {
        assert.throws(() => configFromEnv({ ...ENV, UPSTREAM_URL: 'http://gateway.example/routes/x' }), /must be https/);
    });

    it('allows localhost, so it can run without the Gateway', () => {
        assert.ok(configFromEnv({ ...ENV, UPSTREAM_URL: 'http://localhost:9999/routes/x' }));
    });

    it('refuses an upstream that points back at the proxy', () => {
        assert.throws(() => configFromEnv({ ...ENV, UPSTREAM_URL: 'https://proxy.example.com/mcp/' }), /points back/);
    });

    it('keeps the issuer exactly as configured, trailing slash included', () => {
        assert.equal(configFromEnv({ ...ENV, OIDC_ISSUER: 'https://tenant.auth0.com/' }).issuer, 'https://tenant.auth0.com/');
    });

    it('offers the Gateway JSON only by default, and can be overridden', () => {
        assert.equal(CONFIG.upstreamAccept, 'application/json');
        assert.match(configFromEnv({ ...ENV, UPSTREAM_ACCEPT: 'application/json, text/event-stream' }).upstreamAccept, /event-stream/);
    });
});

describe('the precheck', () => {
    const check = (t: string) => precheck(decodeClaims(t), CONFIG);

    it('passes a well-formed token', () => assert.equal(check(token()), undefined));
    it('refuses something that is not a JWT', () => assert.equal(check('opaque'), 'not a JWT'));
    it('refuses another issuer', () => assert.match(check(token({ iss: 'https://evil.example' })) ?? '', /issuer/));
    it('refuses an expired token', () => assert.equal(check(token({ exp: 1 })), 'expired'));
    it('refuses a token with no expiry', () => assert.equal(check(token({ exp: undefined })), 'expired'));
    it('refuses a token minted for another resource', () => assert.match(check(token({ aud: 'other' })) ?? '', /audience/));
    it('accepts the audience inside a list', () => assert.equal(check(token({ aud: ['account', ENV.JWT_AUDIENCE] })), undefined));
    it('ignores audience when none is configured', () => {
        assert.equal(precheck(decodeClaims(token({ aud: 'other' })), { ...CONFIG, audience: undefined }), undefined);
    });
});

describe('discovery', () => {
    it('puts the metadata path after the well-known prefix', () => {
        assert.equal(resourceMetadataUrl(CONFIG.publicUrl), 'https://proxy.example.com/.well-known/oauth-protected-resource/mcp');
    });

    it('publishes RFC 9728 metadata naming the IdP', async () => {
        const { handle } = proxy(reply());
        for (const path of ['/.well-known/oauth-protected-resource/mcp', '/.well-known/oauth-protected-resource']) {
            const response = await handle(new Request(`https://proxy.example.com${path}`));
            const body = (await response.json()) as Record<string, unknown>;
            assert.equal(body.resource, 'https://proxy.example.com/mcp');
            assert.deepEqual(body.authorization_servers, [ISSUER]);
            assert.deepEqual(body.scopes_supported, ['openid', 'email', 'offline_access']);
        }
    });

    it('challenges a request with no token, pointing at the metadata', async () => {
        const response = await proxy(reply()).call(null);
        assert.equal(response.status, 401);
        assert.equal(
            response.headers.get('www-authenticate'),
            'Bearer resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource/mcp"'
        );
    });

    it('challenges an expired token without calling the Gateway', async () => {
        let called = false;
        const response = await proxy(async () => ((called = true), new Response())).call(token({ exp: 1 }));
        assert.equal(response.status, 401);
        assert.match(response.headers.get('www-authenticate') ?? '', /error="invalid_token".*resource_metadata=/);
        assert.equal(called, false);
    });

    it('declines GET and DELETE on the resource, as Streamable HTTP allows', async () => {
        const { handle } = proxy(reply());
        assert.equal((await handle(new Request(CONFIG.publicUrl))).status, 405);
    });
});

describe('forwarding', () => {
    it('sends the token, a JSON-only Accept and the MCP headers to the Gateway route', async () => {
        let seen: { url: string; headers: Record<string, string>; body: string } | undefined;
        const { handle } = proxy(async (url, init) => {
            seen = { url: String(url), headers: init?.headers as Record<string, string>, body: String(init?.body) };
            return reply()();
        });
        const bearer = token();
        await handle(
            new Request(CONFIG.publicUrl, {
                method: 'POST',
                headers: { authorization: `Bearer ${bearer}`, 'mcp-session-id': 's-1', cookie: 'not-forwarded' },
                body: '{"jsonrpc":"2.0","id":7,"method":"tools/list"}'
            })
        );
        assert.equal(seen?.url, UPSTREAM);
        assert.equal(seen?.headers.authorization, `Bearer ${bearer}`);
        assert.equal(seen?.headers.accept, 'application/json');
        assert.equal(seen?.headers['mcp-session-id'], 's-1');
        assert.equal(seen?.headers.cookie, undefined);
        assert.equal(seen?.body, '{"jsonrpc":"2.0","id":7,"method":"tools/list"}');
    });

    it('also sends the token under FORWARD_TOKEN_HEADER when set', async () => {
        let headers: Record<string, string> | undefined;
        const config = configFromEnv({ ...ENV, FORWARD_TOKEN_HEADER: 'X-Lab-Participant-Token' });
        const bearer = token();
        await proxy(async (_url, init) => ((headers = init?.headers as Record<string, string>), reply()()), config).call(bearer);
        assert.equal(headers?.['x-lab-participant-token'], bearer);
    });

    it('relays status, body and session id', async () => {
        const response = await proxy(
            reply('{"jsonrpc":"2.0","id":7,"result":{"tools":[]}}', { headers: { 'content-type': 'application/json', 'mcp-session-id': 's-2' } })
        ).call();
        assert.equal(response.status, 200);
        assert.equal(response.headers.get('mcp-session-id'), 's-2');
        assert.deepEqual(await response.json(), { jsonrpc: '2.0', id: 7, result: { tools: [] } });
    });

    it('relays a server-sent event stream', async () => {
        const response = await proxy(reply('data: {}\n\n', { headers: { 'content-type': 'text/event-stream' } })).call();
        assert.match(response.headers.get('content-type') ?? '', /event-stream/);
        assert.match(await response.text(), /^data: /);
    });

    it('turns a Gateway 401 into a terminal 502, never relaying its challenge', async () => {
        // Relaying it would restart a sign-in that already worked.
        const response = await proxy(
            reply('{"detail":"unauthorized"}', { status: 401, headers: { 'www-authenticate': 'Bearer resource_metadata="/x"' } })
        ).call();
        assert.equal(response.status, 502);
        assert.equal(response.headers.get('www-authenticate'), null);
        const body = (await response.json()) as { error: { message: string }; id: unknown };
        assert.match(body.error.message, /refused/);
        assert.equal(body.id, 7);
    });

    it('turns a trust-policy 403 into a 502', async () => {
        assert.equal((await proxy(reply('denied', { status: 403 })).call()).status, 502);
    });

    it('answers 502 when the Gateway is unreachable, keeping the JSON-RPC id', async () => {
        const response = await proxy(async () => {
            throw new TypeError('fetch failed');
        }).call();
        assert.equal(response.status, 502);
        assert.equal(((await response.json()) as { id: unknown }).id, 7);
    });

    it('refuses an oversized body', async () => {
        assert.equal((await proxy(reply()).call(token(), { pad: 'x'.repeat(1_100_000) })).status, 413);
    });
});

describe('over real HTTP, against a stub Gateway', () => {
    const start = (server: Server) =>
        new Promise<string>(resolve => {
            server.on('listening', () => resolve(`http://127.0.0.1:${(server.address() as AddressInfo).port}`));
            after(() => server.close());
        });

    it('discovers, challenges, then streams the upstream reply through', async () => {
        const gateway = createServer((_req, res) => {
            res.writeHead(200, { 'content-type': 'text/event-stream' });
            res.end('data: {"jsonrpc":"2.0","id":1,"result":{}}\n\n');
        }).listen(0);
        const upstream = await start(gateway);

        const config = configFromEnv({ ...ENV, PUBLIC_URL: 'http://localhost/mcp', UPSTREAM_URL: `${upstream}/route` });
        const base = await start(listen(createProxy(config, { log: silent }), 0, silent));

        const challenge = await fetch(`${base}/mcp`, { method: 'POST', body: '{}' });
        assert.equal(challenge.status, 401);
        const metadata = await fetch(`${base}/.well-known/oauth-protected-resource/mcp`);
        assert.equal(((await metadata.json()) as { resource: string }).resource, 'http://localhost/mcp');

        const response = await fetch(`${base}/mcp`, {
            method: 'POST',
            headers: { authorization: `Bearer ${token()}`, 'content-type': 'application/json' },
            body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}'
        });
        assert.equal(response.status, 200);
        assert.match(response.headers.get('content-type') ?? '', /event-stream/);
        assert.match(await response.text(), /"id":1/);
    });
});
