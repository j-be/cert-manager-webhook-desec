# Solver testdata directory

Before running tests, copy the file `examples/desec-token.yaml` file to this directory, and substitute **_<API-Token-(Base64-encoded)>_** with base64-encoded deSEC api token.

Run the test with the following, setting **TEST_ZONE_NAME** to one of your deSEC domains.

```bash
$ TEST_ZONE_NAME=example.com make test
```
