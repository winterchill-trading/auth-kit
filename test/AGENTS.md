# test: expect tests, properties and the CLI cram test

- One file per module; Quickcheck properties sit next to the expect tests.
- `test_step_up_policy.ml` uses Async and `service-kit`; other files stay pure.
- Promote with `dune promote` (same `DUNE_BUILD_DIR`) after reading the diff. Pinned
  `[%bin_digest]` values changing means a stored format changed.
- `cli.t/run.t` is the cram test for the `auth-kit` binary.
