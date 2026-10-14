# bin: the `auth-kit` CLI

`main.ml`: `hash`, `verify HASH`, `inspect HASH`, `bench`, `check-passcode`. Secrets are read
from stdin only, never from arguments. Covered by `test/cli.t/run.t`.
