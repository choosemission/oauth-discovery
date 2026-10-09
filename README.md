# mcp-auth-discovery

An OAuth discovery front for an MCP server behind an Affinidi Agent Gateway route.

**This is a proxy, not only a discovery document.** Every MCP request goes
through it to the Gateway.

**It is a workaround.** It is meant to be used only until an Agent Surface
supports [Authorization Server Discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery)
from the MCP authorization spec: a 401 challenge whose `resource_metadata`
points at RFC 9728 metadata naming the authorization server. Once the Gateway
serves that itself, point clients at the access point directly and retire this.

## Why

Point an MCP client straight at an Agent Gateway access point and sign-in
fails. The Gateway answers with a correct `401`, but the discovery documents
that challenge points at return the dashboard's HTML. The client follows the
pointer, gets a web page, and stops.

This front owns its own URL and does the part the Gateway can't do yet:

```
MCP client
   │  POST https://front.example.com/mcp
   │  401 → RFC 9728 metadata → sign in at your IdP → Bearer <token>
   ▼
this front     publishes metadata, answers the 401 challenge, forwards with the token
   │  Authorization: Bearer <the same token>
   ▼
Agent Gateway  verifies the token, applies trust policy, injects credentials, audits
   │
   ▼
your MCP server
```

## The access point must verify the token

**The front does not verify tokens.** It decodes the token without checking the
signature and confirms that the issuer, expiry and (optionally) audience look
right. Anyone can forge a token that passes this check. All it does is decide
whether the client should be asked to sign in again (`401`) or whether the
Gateway is misconfigured (a terminal `502`, so the client doesn't loop through
sign-in forever).

Real verification is the Gateway's job. Before you put this front in front of
your access point, configure on the access point:

- a **JWT verification strategy** that trusts your IdP's issuer; and
- **caller identity extraction**. Without it, the Gateway verifies the token
  but has no claim to attribute the call to, and returns `200` with an empty body.

If the access point accepts unauthenticated calls, this front is an open door.

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
| `PUBLIC_URL` | This front's public URL: the OAuth resource identifier |
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

`src/front.ts` is a web-standard `fetch(Request) → Response` handler, and
`src/node.ts` adapts it to Node's http server.
