# Cross-server conformance

`conformance.js` is the shared security and wire-contract suite for the Go,
Node, and Python servers. It intentionally does not compare detector scores;
those implementations still have documented detection differences. It pins the
invariants where a difference is a security or integration defect:

- proof of work is required;
- tokens and challenges are single-use;
- signal commitments cannot be swapped;
- token verification authentication and optional visitor-IP binding;
- signed hostname, action, and cdata claims;
- Siteverify form encoding, shape, and idempotency;
- request-size and HEAD behavior.

Run a server with the same secret exported to the test process, then:

```bash
FCAPTCHA_SECRET=conformance-test-secret node test/conformance.js http://localhost:3000
```

CI builds each production container and runs this exact file against it.

`redis-conformance.js` is the multi-replica companion. CI starts two production
containers against one Redis service and proves that a challenge issued by one
replica verifies on the other, token replay is rejected across replicas, and a
Siteverify idempotency response created on one replica is returned by the other.
The same test runs unchanged against Go, Node, and Python.
