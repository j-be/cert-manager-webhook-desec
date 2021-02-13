# deSEC Webhook for cert-manager

A [cert-manager](https://github.com/jetstack/cert-manager) webhook to solve an ACME DNS01 challenge using the [deSEC](https://desec.io/) API

## Prerequisites

A Kubernetes cluster with cert-manager deployed. If you haven't already installed cert-manger, follow the guide [here](https://cert-manager.io/docs/installation/kubernetes/).

## Deployment

### Using regular manifests

An example webhook deployment, with it's associated roles, role bindings, service and required tls certificates, is provided in the file `examples/deploy/desec-webhook.yaml`. The example manifest will deploy to the default namespace. To set a different namespace, replace all instances of `default` with the namespace of your choice. Don't miss the annotation ` cert-manager.io/inject-ca-from` in the `APIService` or the `dnsNames` for the webhook `Certificate`. The following will replace all the necessary namespace references in the example manifest:

```bash
$ sed -i 's/default/yournamespace/g' examples/deploy/desec-webhook.yaml
```

Once you're satisfied with the changes, deploy the webhook with:

```bash
$ kubectl apply -f examples/deploy/desec-webhook.yaml
```

### Using Helm

TODO

## Usage

### Deploy an API Token Secret

The deSEC API token needs to placed into a kubernetes secret. You can use the file `examples\desec-token.yaml` as a starting point. Place your Base64-encoded API token into the manifest. This can be obtained with:

```bash
$ echo -n "your-api-token" | base64
```

### Deploy an Issuer

An example `ClusterIssuer` is provided in the `examples/letsencrypt-staging-issuer.yaml` file. It uses the letsencrypt staging server, but it can be adapted for the letsencrypt production server or other acme server. `Issuer` can be used instead of `ClusterIssuer` if you only want to issue certificates in a single namespace.

### Deploy a Certificate

An example certificate manifest is provide in `examples/test-certificate.yaml`. Edit as required for production certificates.

## Building

```bash
$ make build
```

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.

**It is essential that you configure and run the test suite when creating a
DNS01 webhook.**

An example Go test file has been provided in [main_test.go](https://github.com/cert-manager/webhook-example/blob/master/main_test.go).

You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. make test
```

The example file has a number of areas you must fill in and replace with your
own options in order for tests to pass.

See [here](./testdata/desec/README.md) for testing details.
