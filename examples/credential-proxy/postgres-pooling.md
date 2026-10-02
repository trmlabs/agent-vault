# PostgreSQL pooling (transaction mode)

With pooling on, the broker multiplexes many client sessions onto a few server connections per worker pool and database, the way a transaction-mode pooler does. Each set of server connections uses one Vault credential, which rotates in the background, so the database sees a small, steady number of logins however many workers connect. Enable it with `AGENT_VAULT_DB_POOLING=true`. Without it, each client session keeps its own server connection and credential, as before.

## How a session runs

- **Binding.** A client takes a server connection when it sends a statement and hands it back when the server reports the transaction finished (ReadyForQuery `I`) and nothing it sent is unanswered. An open (`T`) or failed (`E`) transaction keeps the connection.
- **Prepared statements** work as usual. The broker names them on the server by their text and prepares them again on whichever connection a client gets, so clients that reuse a name for different queries never collide.
- **Startup parameters** (`TimeZone`, `DateStyle`, `search_path`, `statement_timeout`, `extra_float_digits`, `standard_conforming_strings`) are applied to each connection a client gets, and reset for the next client. Only UTF8 is supported.
- **Session state pins.** `SET` (other than `SET LOCAL`), `RESET`, `LISTEN`, temporary tables, `PREPARE`, `DISCARD`, `WITH HOLD` cursors, `set_config` and session advisory locks pin the connection to that client until it disconnects. Pinned connections are capped at 10% of the database's budget. A statement that would exceed the cap is refused with SQLSTATE 53300, and the session continues. A pinned connection runs `DISCARD ALL` before anyone else uses it. Detection is a conservative keyword scan: a function that changes session state internally is not detected, so do not grant such functions to pooled roles.
- **Ending.** A client that disconnects inside a transaction, or with statements in flight, has its server connection closed, never reused. A terminated session (revoked access, the Pod's deadline) cancels its running statement first.
- **Cancel** requests reach whichever server connection the session holds at that moment.

## Budgets

Each database's server-connection budget is its catalog `maxConns` (for example 150 for core, 300 for others), divided by `AGENT_VAULT_DB_POOL_REPLICAS`. It defaults to 50 when unset. When every connection is busy, a statement waits up to 2 seconds in a queue bounded at twice the budget. Past either bound it is refused with SQLSTATE 53300 and can be retried. `AGENT_VAULT_DB_MAX_CONNS` caps client sessions in pooled mode.

## Credentials

A pool's first credential is minted on first use. At half its lifetime, with up to 10% jitter per pool, the next is minted. New connections use it; connections on the old one finish their current transaction and close. The old credential is revoked once its last connection closes, or at its expiry if a transaction is still running. Each pooled credential is one record in the cleanup journal. Retiring a worker Pod depends only on its own client sessions, because no credential belongs to a Pod.

## Audit

Each client session records `session_open` and `session_close`, and each transaction records a `transaction` row with its outcome (`completed` or `failed`) and duration. No row carries SQL text.
