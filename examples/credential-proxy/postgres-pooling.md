# PostgreSQL pooling (transaction mode)

With pooling on, the broker multiplexes many client sessions onto a few server connections per worker pool and database, the way a transaction-mode pooler does. Each set of server connections uses one Vault credential, which rotates in the background, so the database sees a small, steady number of logins however many workers connect. Enable it with `AGENT_VAULT_DB_POOLING=true`. Without it, each client session keeps its own server connection and credential, as before.

## How a session runs

- **Binding.** A client takes a server connection when it sends a statement and hands it back when the server reports the transaction finished (ReadyForQuery `I`) and nothing it sent is unanswered. An open (`T`) or failed (`E`) transaction keeps the connection.
- **Prepared statements** work as usual. The broker names them on the server by their text and prepares them again on whichever connection a client gets, so clients that reuse a name for different queries never collide.
- **Startup parameters** that drivers send by default are accepted: `application_name`, `client_encoding` (any encoding, such as libpq's `SQL_ASCII` under the C locale), `DateStyle`, `TimeZone`, `extra_float_digits`, `search_path`, `standard_conforming_strings` and `statement_timeout`. Each is applied to whichever connection a client gets, in one query, and reset for the next client. Tested with node-postgres 8 defaults (user and database only) and libpq defaults (what psycopg sends), under UTF-8 and C locales.
- **Session state pins, fail-safe.** The broker lexes every statement in both protocols: simple-protocol `Query` text and extended-protocol `Parse` text, with comments, quoted strings, E-strings, dollar quotes and quoted identifiers understood. A statement stays in transaction mode only if it starts with a keyword known to leave no session state (for example `SELECT`, `INSERT`, `BEGIN`, `COMMIT`, non-temporary DDL, `SET LOCAL`), and calls no function known to set state. Everything else pins the connection to the client: session `SET`, `RESET`, `LISTEN`, temporary tables, anything naming the temporary schema (`pg_temp`), `PREPARE`, `DO`, `CALL`, unknown statements, and unterminated text. Pinned connections are capped at 10% of the database's budget. A pin beyond the cap is refused with SQLSTATE 53300, and the session continues. A pinned connection runs `DISCARD ALL` before anyone else uses it.
- **Refused outright.** `ALTER ROLE`, `ALTER USER`, `ALTER GROUP` and `ALTER DATABASE` are refused with SQLSTATE 42501 and never reach the server: on the shared login they would change defaults or the password for every later client. A session may hold at most 1,000 named prepared statements and 16 MiB of their text; beyond that, `Parse` is refused with SQLSTATE 54000.
- **Check-in backstop.** After each transaction, once the client has its answer, the broker checks the connection before reuse. It looks for a reported parameter left changed, a temporary table, type, function or operator, a listened channel, a session advisory lock, a holdable cursor, a SQL-level prepared statement, a role switched with `SET ROLE`, a broker-applied parameter no longer at the broker's value, or any other setting changed for the session, and drops sequence state (`DISCARD SEQUENCES`). If it finds state, it runs `DISCARD ALL` and writes a `state_leak_caught` audit row. If the login's own role-level defaults changed, which `DISCARD ALL` cannot undo, it closes the connection, retires the credential and audits `role_defaults`. This catches what lexing cannot see, such as a function that calls `set_config` internally. It costs one round trip per transaction, after the client's response.
- **Ending.** A client that disconnects inside a transaction, or with statements in flight, has its server connection closed, never reused. A terminated session (revoked access, the Pod's deadline) cancels its running statement first, on a connection already detached from the pool. A client idle inside a transaction for 5 minutes loses its session (the server's `idle_in_transaction_session_timeout`), and one that stops reading for 30 seconds is disconnected, so neither can hold a server connection.
- **Cancel** requests reach whichever server connection the session holds at that moment.

## Read-only logins

PostgreSQL lets every login create temporary tables, views and sequences unless the database revokes `TEMP` from `PUBLIC`. On a read-only login the broker refuses them itself, so no database change is needed, pooled or not. A login is read-only when its catalog entry has `access: read` (the default), or, for services outside the catalog, when its Vault role name ends in `-readonly`.

The broker refuses, with SQLSTATE 25006 and a message that names the read-only login:

- `CREATE ... TEMP` or `TEMPORARY` (tables, views, sequences, `CREATE TABLE AS`, also under `EXPLAIN ANALYZE`) and `SELECT ... INTO TEMP`.
- Anything that names `pg_temp`, anywhere in the text, and a startup `search_path` that names it.
- Statements that could create one where the broker cannot see it: `DO` blocks, `set_config`, `UPDATE pg_settings`, Unicode-escaped names (`U&"..."`), escape strings in a `search_path` change, and the fast-path `FunctionCall` message.
- `SET` of `standard_conforming_strings`, `client_encoding` or `NAMES`, which could make the server read later text differently from the broker. A lone `SET` to a value the startup allowlist accepts (`on`, or a server encoding such as `UTF8`) is allowed, so drivers that set them on connect keep working.

Pooled, the refusal is an `ERROR` and the session continues. Unpooled, the broker reads each client message whole before relaying it, and a refusal ends the session with a `FATAL`. Either way the statement never reaches the database, and the broker writes a `denied` audit row with outcome `read_only_temp`. Read-write logins are unchanged. An existing function in the database that creates a temporary table when called is not covered; the database's own privileges govern what functions a read-only login can call.

## Entitlement tiers

The pool key holds everything that decides privileges: the worker pool, the binding, the Vault mount and role, and the upstream address and database. Two entitlement tiers are two bindings with two database roles, so their clients never share a server connection. A binding whose role changes in the catalog gets new connections and a new credential.

## Budgets

Each database's server-connection budget is its catalog `maxConns` (for example 150 for core, 300 for others), divided by `AGENT_VAULT_DB_POOL_REPLICAS`. It defaults to `AGENT_VAULT_DB_POOL_BUDGET`, or 50, when unset. When every connection is busy, a statement waits up to 2 seconds in a queue bounded at twice the budget. Past either bound it is refused with SQLSTATE 53300 and can be retried. `AGENT_VAULT_DB_MAX_CONNS` caps client sessions in pooled mode.

## Credentials

A pool's first credential is minted on first use. At half its lifetime, with up to 10% jitter per pool, the next is minted. New connections use it; connections on the old one finish their current transaction and close. The old credential is revoked once its last connection closes. At its expiry the broker closes every connection still on it and revokes it, without relying on the Vault role's revocation to end those sessions. Each pooled credential is one record in the cleanup journal. Retiring a worker Pod depends only on its own client sessions, because no credential belongs to a Pod.

## Audit

Each client session records `session_open` and `session_close`, and each transaction records a `transaction` row with its outcome (`completed` or `failed`) and duration. A check-in that resets leaked state records `state_leak_caught`. No row carries SQL text.
