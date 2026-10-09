# OAuth Discovery

An OAuth discovery proxy for Agent Surfaces on an
[Affinidi Agent Gateway](https://www.affinidi.com/). It lets an agent client
sign in to a service whose access point requires a JWT, using nothing but a URL.

## What this repo is for

You have a service behind an Agent Surface, and the access point requires a
bearer token from your IdP. A client should be able to connect with just a URL,
find out where to sign in, get a token, and call the service. Today it can't,
because the Gateway's OAuth discovery is broken (see [Why](#why)).

This repo is a small proxy you run in front of that access point:

1. It owns a public URL and publishes
   [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) protected-resource
   metadata naming your IdP.
2. It answers unauthenticated requests with a `401` challenge that points at
   that metadata, so the client knows where to sign in.
3. It forwards every request that carries a token to the access point, which
   verifies the token, applies policy and calls your service.

**What works today.** MCP servers (Streamable HTTP) are supported and tested
end to end. Discovery itself is plain HTTP OAuth, and the forwarding handles
any JSON-RPC-over-`POST` protocol, so A2A's JSON-RPC binding is close. A2A
clients also read sign-in details from the agent card at
`/.well-known/agent-card.json`, though, and this proxy does not serve or pass
that through yet.

**What it is not.** It is not an authorization server or a token verifier:
your IdP issues tokens, and the access point verifies them (see
[below](#the-access-point-must-verify-the-token)). It is not only a discovery
document either: every request goes through it.

**It is a workaround.** It is meant to be used only until an Agent Surface
supports [Authorization Server Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery)
itself: a `401` challenge whose `resource_metadata` points at RFC 9728 metadata
naming the authorization server. Once the Gateway serves that, point clients at
the access point directly and retire this.

Not affiliated with Affinidi.

## Why

Point a client (an MCP client, for example) straight at an Agent Gateway
access point and sign-in fails. The Gateway answers with a correct `401`, but the discovery documents
that challenge points at return the dashboard's HTML. The client follows the
pointer, gets a web page, and stops.

This proxy owns its own URL and does the part the Gateway can't do yet:

```
agent client
   │  POST https://proxy.example.com/mcp
   │  401 → RFC 9728 metadata → sign in at your IdP → Bearer <token>
   ▼
this proxy     publishes metadata, answers the 401 challenge, forwards with the token
   │  Authorization: Bearer <the same token>
   ▼
Agent Gateway  verifies the token, applies trust policy, injects credentials, audits
   │
   ▼
your service (an MCP server, say)
```

## The access point must verify the token

**The proxy does not verify tokens.** It decodes the token without checking the
signature and confirms that the issuer, expiry and (optionally) audience look
right. Anyone can forge a token that passes this check. All it does is decide
whether the client should be asked to sign in again (`401`) or whether the
Gateway is misconfigured (a terminal `502`, so the client doesn't loop through
sign-in forever).

Real verification is the Gateway's job. Before you put this proxy in front of
your access point, configure on the access point:

- a **JWT verification strategy** that trusts your IdP's issuer; and
- **caller identity extraction**. Without it, the Gateway verifies the token
  but has no claim to attribute the call to, and returns `200` with an empty body.

If the access point accepts unauthenticated calls, this proxy is an open door.

## Run it

Needs Node 22.18 or later. There are no runtime dependencies.

```sh
cp .env.example .env   # then fill it in
npm start
```

Then point your MCP client at `PUBLIC_URL`. It has to be reachable over HTTPS
by the client and by the IdP's redirect flow.

### Configuration

See [`.env.example`](./.env.example) for every variable. The ones that matter:

| Variable | What it is |
| --- | --- |
| `PUBLIC_URL` | This proxy's public URL: the OAuth resource identifier |
| `UPSTREAM_URL` | The Agent Gateway route to forward to |
| `OIDC_ISSUER` | Your IdP, compared to `iss` exactly |
| `JWT_AUDIENCE` | If set, `aud` must contain it |
| `SCOPES` | Advertised to clients. With Keycloak, include your audience scope |

### Keycloak and the audience

Keycloak ignores RFC 8707 `resource`, so a token's `aud` comes only from a
client scope with an audience mapper. A client receives a scope only if it asks
for it, and it asks for what `SCOPES` advertises. Leave the audience scope out
and sign-in looks successful, but the token has no `aud` and fails the check.
Set `JWT_AUDIENCE` to what the mapper emits, which is usually not `PUBLIC_URL`.

## What it does to traffic

- Serves `/.well-known/oauth-protected-resource{path}` and the same document
  at the bare prefix.
- Accepts `POST` on `PUBLIC_URL`'s path and answers `405` to anything else
  there, as Streamable HTTP allows.
- Forwards the body unchanged, with `Authorization`, the MCP headers
  (`mcp-protocol-version`, `mcp-session-id`, `last-event-id`) and
  `Accept: $UPSTREAM_ACCEPT`. Nothing else from the client is passed on.
- Never relays the Gateway's `WWW-Authenticate`. A Gateway `401` or `403` on a
  token that passed the check becomes a `502` with a JSON-RPC error.
- Streams the response back.

## Develop

```sh
npm install        # TypeScript, for the typecheck only
npm test
npm run typecheck
```

`src/proxy.ts` is a web-standard `fetch(Request) → Response` handler, and
`src/node.ts` adapts it to Node's http server.
