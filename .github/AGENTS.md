# .github: CI

`workflows/ci.yml` installs `libargon2-dev`, runs the infra ox-setup action with the
`service-kit` pin (test dependency), builds, runs the example and the tests. Keep the pins in
step with the `depends` in `dune-project`.
