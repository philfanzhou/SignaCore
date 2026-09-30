# Management runtime information

The completed host maps `GET /management/v1/runtime` in the existing management API v1
group. A valid administrator management Cookie or Bearer receives `200 application/json`
with exactly these four fields in this order:

```json
{"serviceName":"signacore","serviceVersion":"1.0.0","instanceId":"signacore-example","phase":"Completed"}
```

The version and instance ID above are illustrative. The service identity is fixed when that
host is built; the instance ID remains constant for its lifetime and differs between hosts.
These values are non-secret operational metadata, never configuration or connection details.

The existing phase gate observes installation, migration, and database readiness once. The
handler reports the admitted `Completed` phase and performs no extra health or database read.
It does not promise that another host, or the response write time, has the same health state.
Bootstrap and Setup do not map the runtime endpoint; the management-prefix phase gate rejects
it with `503 {"errorCode":"service.phase.unavailable"}`. Normal-host lost installation
authority or a failed observation also produces that rejection. Methods other than GET,
including HEAD, are rejected by the phase gate.

Anonymous or invalid credentials receive the existing fixed 401 error codes; an authenticated
operator without Admin permission receives 403. Any Authorization header selects Bearer and
cannot fall back to a Cookie. Exhausted budgets retain SignaCore's existing 429 JSON response.
Caller cancellation propagates through the phase observation. Responses retain all six shared
security headers, including `Cache-Control: no-store`, and one `x-correlation-id`; concurrent
requests retain independent correlation and cancellation state.

No new setting, database migration, cache, background polling, or anonymous diagnostic endpoint
is introduced. Rollback removes this opt-in mapping and its documentation. Existing clients and
JWT/JWKS contracts are unaffected.
