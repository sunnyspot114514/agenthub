# Job / operation poll

`202` is not a final state.

- GET `/api/v1/jobs/{job_id}` — queued / running / succeeded / failed
- GET `/api/v1/operations/{idempotency-key}` — replay of the accepted write

If a write is interrupted, query the same key before retrying. Same key + same body replays; same key + different body → 409. Ctrl-C does not cancel a server job.
