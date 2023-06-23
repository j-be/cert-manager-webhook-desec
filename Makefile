IMAGE_NAME := "kmorning/cert-manager-webhook-desec"
IMAGE_TAG := "latest"

OUT := $(shell pwd)/_out

KUBEBUILDER_VERSION=2.3.1
KUBEBUILDER_URL=https://github.com/kubernetes-sigs/kubebuilder/releases/download/v$(KUBEBUILDER_VERSION)/kubebuilder_$(KUBEBUILDER_VERSION)_linux_amd64.tar.gz
KUBEBUILDER_TGZ=$(OUT)/kubebuilder/kubebuilder_$(KUBEBUILDER_VERSION)_linux_amd64.tar.gz
KUBEBUILDER_BIN=$(OUT)/kubebuilder/bin

$(shell mkdir -p "$(KUBEBUILDER_BIN)")

$(KUBEBUILDER_TGZ):
	curl -sfL $(KUBEBUILDER_URL) -o $(KUBEBUILDER_TGZ)

prepare: $(KUBEBUILDER_TGZ)
	tar xvzf $(KUBEBUILDER_TGZ) --strip-components=1 -C _out/kubebuilder

$(KUBEBUILDER_BIN)/etcd: prepare
$(KUBEBUILDER_BIN)/kube-apiserver: prepare
$(KUBEBUILDER_BIN)/kubebuilder: prepare
$(KUBEBUILDER_BIN)/kubectl: prepare

test: $(KUBEBUILDER_BIN)/etcd $(KUBEBUILDER_BIN)/kube-apiserver $(KUBEBUILDER_BIN)/kubebuilder $(KUBEBUILDER_BIN)/kubectl
	go test -v .

build:
	docker build -t "$(IMAGE_NAME):$(IMAGE_TAG)" .

.PHONY: rendered-manifest.yaml
rendered-manifest.yaml:
	helm template desec-webhook \
        --set image.repository=$(IMAGE_NAME) \
        --set image.tag=$(IMAGE_TAG) \
        deploy/desec-webhook > "$(OUT)/rendered-manifest.yaml"
