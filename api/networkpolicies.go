package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// DataCenterFile represents the overall JSON structure.
type DataCenterFile struct {
	Version     string             `json:"version"`
	Description string             `json:"description"`
	Objects     []DataCenterObject `json:"objects"`
}

// DataCenterObject represents an individual object within the JSON structure.
type DataCenterObject struct {
	Name        string   `json:"name"`
	ID          string   `json:"id"`
	Description string   `json:"description"`
	Ranges      []string `json:"ranges"`
}

// GetNetworkPolicyEgressCIDRs returns a JSON string formatted according to the selected view:
// "all" (default): one aggregated object;
// "policy": one object per NetworkPolicy;
// "namespace": one object per namespace.
func GetNetworkPolicyEgressCIDRs(view string) (string, error) {
	// Initialize k8s client using in-cluster configuration.
	config, err := rest.InClusterConfig()
	if err != nil {
		return "", err
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return "", err
	}

	// List all NetworkPolicies in all namespaces.
	networkPolicies, err := clientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("network policies not found")
		} else if statusError, isStatus := err.(*apierrors.StatusError); isStatus {
			return "", fmt.Errorf("error getting network policies: %v", statusError.ErrStatus.Message)
		} else {
			return "", err
		}
	}

	var objects []DataCenterObject

	switch view {

	case "policy":
		// Create one DataCenterObject per NetworkPolicy.
		for _, np := range networkPolicies.Items {
			// Collect unique CIDRs from egress rules.
			cidrSet := make(map[string]struct{})
			for _, egress := range np.Spec.Egress {
				for _, peer := range egress.To {
					if peer.IPBlock != nil {
						cidrSet[peer.IPBlock.CIDR] = struct{}{}
					}
				}
			}
			cidrs := make([]string, 0, len(cidrSet))
			for cidr := range cidrSet {
				cidrs = append(cidrs, cidr)
			}
			// Use a composite name (namespace/policy) for uniqueness.
			objectName := fmt.Sprintf("%s/%s", np.Namespace, np.Name)
			object := DataCenterObject{
				Name:        objectName,
				ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(objectName)).String(),
				Description: fmt.Sprintf("NetworkPolicy in namespace '%s'", np.Namespace),
				Ranges:      cidrs,
			}
			objects = append(objects, object)
		}

	case "namespace":
		// Group by namespace: aggregate CIDRs from all NetworkPolicies in each namespace.
		nsMap := make(map[string]map[string]struct{})
		for _, np := range networkPolicies.Items {
			if _, exists := nsMap[np.Namespace]; !exists {
				nsMap[np.Namespace] = make(map[string]struct{})
			}
			for _, egress := range np.Spec.Egress {
				for _, peer := range egress.To {
					if peer.IPBlock != nil {
						nsMap[np.Namespace][peer.IPBlock.CIDR] = struct{}{}
					}
				}
			}
		}
		// Create one DataCenterObject per namespace.
		for ns, cidrSet := range nsMap {
			cidrs := make([]string, 0, len(cidrSet))
			for cidr := range cidrSet {
				cidrs = append(cidrs, cidr)
			}
			object := DataCenterObject{
				Name:        ns,
				ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(ns)).String(),
				Description: fmt.Sprintf("All NetworkPolicies in namespace '%s'", ns),
				Ranges:      cidrs,
			}
			objects = append(objects, object)
		}

	default:
		// Default "all" view: aggregate all unique CIDRs across all NetworkPolicies.
		cidrSet := make(map[string]struct{})
		for _, np := range networkPolicies.Items {
			for _, egress := range np.Spec.Egress {
				for _, peer := range egress.To {
					if peer.IPBlock != nil {
						cidrSet[peer.IPBlock.CIDR] = struct{}{}
					}
				}
			}
		}
		cidrs := make([]string, 0, len(cidrSet))
		for cidr := range cidrSet {
			cidrs = append(cidrs, cidr)
		}
		objectName := "All Network Policies"
		object := DataCenterObject{
			Name:        objectName,
			ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(objectName)).String(),
			Description: "Aggregated network policies across all namespaces",
			Ranges:      cidrs,
		}
		objects = append(objects, object)
	}

	dataCenterFile := DataCenterFile{
		Version:     "1.0",
		Description: "Generic Data Center file example",
		Objects:     objects,
	}

	jsonBytes, err := json.MarshalIndent(dataCenterFile, "", "  ")
	if err != nil {
		return "", err
	}

	return string(jsonBytes), nil
}
