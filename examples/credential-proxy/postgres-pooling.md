# PostgreSQL pooling (transaction mode)

With pooling on, the broker multiplexes many client sessions onto a few server connections per worker pool and database, the way a transaction-mode pooler does. Each set of server connections uses one Vault credential, which rotates in the background, so the database sees a small, steady number of logins however many workers connect. Enable it with `AGENT_VAULT_DB_POOLING=true`. Without it, each client session keeps its own server connection and credential, as before.

## How a session runs

- **Binding.** A client takes a server connection when it sends a statement and hands it back when the server reports the transaction finished (ReadyForQuery `I`) and nothing it sent is unanswered. An open (`T`) or failed (`E`) transaction keeps the connection.
- **Prepared statements** work as usual. The broker names them on the server by their text and prepares them again on whichever connection a client gets, so clients that reuse a name for different queries never collide.
- **Startup parameters** that drivers send by default are accepted: `application_name`, `client_encoding` (any encoding, such as libpq's `SQL_ASCII` under the C locale), `DateStyle`, `TimeZone`, `extra_float_digits`, `search_path`, `standard_conforming_strings` and `statement_timeout`. Each is applied to whichever connection a client gets, in one query, and reset for the next client. Tested with node-postgres 8 defaults (user and database only) and libpq defaults (what psycopg sends), under UTF-8 and C locales.
- **Session state pins, fail-safe.** The broker lexes every statement in both protocols: simple-protocol `Query` text and extended-protocol `Parse` text, with comments, quoted strings, E-strings, dollar quotes and quoted identifiers understood. A statement stays in transaction mode only if it starts with a keyword known to leave no session state (for example `SELECT`, `INSERT`, `BEGIN`, `COMMIT`, non-temporary DDL, `SET LOCAL`), and calls no function known to set state. Everything else pins the connection to the client: session `SET`, `RESET`, `LISTEN`, temporary tables, `PREPARE`, `DO`, `CALL`, unknown statements, and unterminated text. Pinned connections are capped at 10% of the database's budget. A pin beyond the cap is refused with SQLSTATE 53300, and the session continues. A pinned connection runs `DISCARD ALL` before anyone else uses it.
- **Check-in backstop.** After each transaction, once the client has its answer, the broker checks the connection before reuse. It looks for a reported parameter left changed, a temporary table, a listened channel, a session advisory lock, a holdable cursor, a broker-applied parameter no longer at the broker's value, or any other setting changed for the session. If it finds one, it runs `DISCARD ALL` and writes a `state_leak_caught` audit row. This catches what lexing cannot see, such as a function that calls `set_config` internally. It costs one round trip per transaction, after the client's response.
- **Ending.** A client that disconnects inside a transaction, or with statements in flight, has its server connection closed, never reused. A terminated session (revoked access, the Pod's deadline) cancels its running statement first.
- **Cancel** requests reach whichever server connection the session holds at that moment.

## Entitlement tiers

The pool key holds everything that decides privileges: the worker pool, the binding, the Vault mount and role, and the upstream address and database. Two entitlement tiers are two bindings with two database roles, so their clients never share a server connection. A binding whose role changes in the catalog gets new connections and a new credential.

## Budgets

Each database's server-connection budget is its catalog `maxConns` (for example 150 for core, 300 for others), divided by `AGENT_VAULT_DB_POOL_REPLICAS`. It defaults to `AGENT_VAULT_DB_POOL_BUDGET`, or 50, when unset. When every connection is busy, a statement waits up to 2 seconds in a queue bounded at twice the budget. Past either bound it is refused with SQLSTATE 53300 and can be retried. `AGENT_VAULT_DB_MAX_CONNS` caps client sessions in pooled mode.

## Credentials

A pool's first credential is minted on first use. At half its lifetime, with up to 10% jitter per pool, the next is minted. New connections use it; connections on the old one finish their current transaction and close. The old credential is revoked once its last connection closes, or at its expiry if a transaction is still running. Each pooled credential is one record in the cleanup journal. Retiring a worker Pod depends only on its own client sessions, because no credential belongs to a Pod.

## Audit

Each client session records `session_open` and `session_close`, and each transaction records a `transaction` row with its outcome (`completed` or `failed`) and duration. A check-in that resets leaked state records `state_leak_caught`. No row carries SQL text.
