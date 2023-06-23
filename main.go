package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog"

	"github.com/jetstack/cert-manager-webhook-desec/desec"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/acme/webhook/cmd"
	cmmeta "github.com/jetstack/cert-manager/pkg/apis/meta/v1"
	"github.com/jetstack/cert-manager/pkg/issuer/acme/dns/util"
)

// GroupName is the API group name (should be unique cluster-wide)
var GroupName = os.Getenv("GROUP_NAME")

type actionType int

const (
	actionPresent actionType = iota
	actionCleanup
)

var actionNames = map[actionType]string{
	actionPresent: "Present",
	actionCleanup: "Cleanup",
}

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&deSECDNSProviderSolver{},
	)
}

// deSECDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/jetstack/cert-manager/pkg/acme/webhook.Solver`
// interface.
type deSECDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client *kubernetes.Clientset
}

// deSECDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type deSECDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`
	APITokenSecretRef cmmeta.SecretKeySelector `json:"apiTokenSecretRef"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *deSECDNSProviderSolver) Name() string {
	return "desec"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *deSECDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	err := c.doAction(ch, actionPresent)
	if err != nil {
		klog.Errorf("Error while presenting record `%s`: %v", ch.ResolvedFQDN, err)
		klog.Flush()
		return err
	}
	klog.Flush()
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *deSECDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	err := c.doAction(ch, actionCleanup)
	if err != nil {
		klog.Errorf("Error while cleaning up record `%s`: %v", ch.ResolvedFQDN, err)
		klog.Flush()
		return err
	}
	klog.Flush()
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *deSECDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	c.client = cl

	return nil
}

// getSecretKey fetch a secret key based on a selector and a namespace
func (c *deSECDNSProviderSolver) getSecretKey(secret cmmeta.SecretKeySelector, namespace string) (string, error) {
	klog.V(6).Infof("retrieving key `%s` in secret `%s/%s`", secret.Key, namespace, secret.Name)

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("secret `%s/%s` not found", namespace, secret.Name)
	}

	data, ok := sec.Data[secret.Key]
	if !ok {
		return "", fmt.Errorf("key `%q` not found in secret `%s/%s`", secret.Key, namespace, secret.Name)
	}

	return string(data), nil
}

func (c *deSECDNSProviderSolver) doAction(ch *v1alpha1.ChallengeRequest, action actionType) error {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return err
	}
	klog.V(2).Infof("%s record `%s`", actionNames[action], ch.ResolvedFQDN)
	// Remove trailing dots from zone and fqdn
	zone := util.UnFqdn(ch.ResolvedZone)
	fqdn := util.UnFqdn(ch.ResolvedFQDN)
	key := ch.Key

	apiToken, err := c.getSecretKey(cfg.APITokenSecretRef, ch.ResourceNamespace)
	if err != nil {
		return err
	}

	api := &desec.API{Token: apiToken}

	// get dns domain from deSEC API
	domain, err := api.GetDNSDomain(zone)
	if err != nil {
		return err
	}

	// Get the subdomain portion of fqdn
	subName := fqdn[:len(fqdn)-len(domain.Name)-1]

	switch action {
	case actionPresent:
		_, err := api.AddRecord(subName, domain.Name, "TXT", key, domain.MinimumTTL)
		return err
	case actionCleanup:
		_, err := api.DeleteRecord(subName, domain.Name, "TXT", key)
		return err
	}
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (deSECDNSProviderConfig, error) {
	cfg := deSECDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
