package api

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"

	"github.com/google/uuid"
	v1 "k8s.io/api/networking/v1"
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

// Pre-parse common private CIDR ranges according to RFC 1918.
// These are used to filter out private IPs from the output.
var privateCIDRs []*net.IPNet

func init() {
	for _, cidr := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			// Log or handle error as needed.
			continue
		}
		privateCIDRs = append(privateCIDRs, network)
	}
}

// isPrivateCIDR returns true if the CIDR falls within any common private IP range.
func isPrivateCIDR(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// If parsing fails, assume it's not private.
		return false
	}
	for _, priv := range privateCIDRs {
		if priv.Contains(ip) {
			return true
		}
	}
	return false
}

// isPublicCIDR returns true if the CIDR is not private.
func isPublicCIDR(cidr string) bool {
	return !isPrivateCIDR(cidr)
}

// cidrContained returns true if child is completely contained in parent.
func cidrContained(child, parent *net.IPNet) bool {
	// Check if parent's network contains child's network start.
	if !parent.Contains(child.IP) {
		return false
	}
	// Calculate the last IP in child's CIDR.
	last := lastIP(child)
	return parent.Contains(last)
}

// lastIP calculates the last IP address in the given IPNet.
// (This implementation works for IPv4 addresses.)
func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		return n.IP
	}
	// Convert IP and mask to big.Int values.
	ipInt := big.NewInt(0).SetBytes(ip)
	mask := net.IP(n.Mask).To4()
	maskInt := big.NewInt(0).SetBytes(mask)

	// Compute the inverted mask.
	invMask := big.NewInt(0).Not(maskInt)
	lastInt := big.NewInt(0).Or(ipInt, invMask)

	// Convert back to net.IP.
	lastIP := lastInt.Bytes()
	// Make sure we have 4 bytes.
	if len(lastIP) < 4 {
		padded := make([]byte, 4)
		copy(padded[4-len(lastIP):], lastIP)
		lastIP = padded
	}
	return net.IP(lastIP)
}

// GetNetworkPolicyEgressCIDRs returns a JSON string formatted according to the selected view:
// "all" (default): one aggregated object;
// "policy": one object per NetworkPolicy;
// "namespace": one object per namespace.
// "internet": two objects—one for public CIDRs and one for private CIDRs.
// "cidr": one object per CIDR provided via the 'providedCIDRs' parameter.
func GetNetworkPolicyEgressCIDRs(view, filterNamespace, filterName, providedCIDRs string) (string, error) {
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
	networkPolicyList, err := clientset.NetworkingV1().NetworkPolicies("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", fmt.Errorf("network policies not found")
		} else if statusError, isStatus := err.(*apierrors.StatusError); isStatus {
			return "", fmt.Errorf("error getting network policies: %v", statusError.ErrStatus.Message)
		} else {
			return "", err
		}
	}

	// If no filtering is provided, use all policies.
	var filteredPolicies []v1.NetworkPolicy
	if filterNamespace == "" && filterName == "" {
		filteredPolicies = networkPolicyList.Items
	} else {
		// Otherwise, filter policies based on namespace and/or name.
		for _, np := range networkPolicyList.Items {
			if filterNamespace != "" && np.Namespace != filterNamespace {
				continue
			}
			if filterName != "" && np.Name != filterName {
				continue
			}
			filteredPolicies = append(filteredPolicies, np)
		}
	}

	var objects []DataCenterObject

	switch view {

	case "policy":
		// Create one DataCenterObject per NetworkPolicy.
		for _, np := range filteredPolicies {
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
		for _, np := range filteredPolicies {
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

	case "internet":
		// Aggregate all CIDRs across all NetworkPolicies.
		cidrSet := make(map[string]struct{})
		for _, np := range filteredPolicies {
			for _, egress := range np.Spec.Egress {
				for _, peer := range egress.To {
					if peer.IPBlock != nil {
						cidrSet[peer.IPBlock.CIDR] = struct{}{}
					}
				}
			}
		}
		// Separate into public and private lists.
		publicCIDRs := make([]string, 0)
		privateCIDRsList := make([]string, 0)
		for cidr := range cidrSet {
			if isPublicCIDR(cidr) {
				publicCIDRs = append(publicCIDRs, cidr)
			} else {
				privateCIDRsList = append(privateCIDRsList, cidr)
			}
		}
		// Create two DataCenterObjects: one for public and one for private.
		publicObjectName := "Public Network Policies"
		publicObject := DataCenterObject{
			Name:        publicObjectName,
			ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(publicObjectName)).String(),
			Description: "Aggregated public network policies across all namespaces",
			Ranges:      publicCIDRs,
		}
		privateObjectName := "Private Network Policies"
		privateObject := DataCenterObject{
			Name:        privateObjectName,
			ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(privateObjectName)).String(),
			Description: "Aggregated private network policies across all namespaces",
			Ranges:      privateCIDRsList,
		}
		objects = append(objects, publicObject, privateObject)

	case "cidr":
		// First, aggregate all unique CIDRs from the filtered policies.
		aggregatedSet := make(map[string]struct{})
		for _, np := range filteredPolicies {
			for _, egress := range np.Spec.Egress {
				for _, peer := range egress.To {
					if peer.IPBlock != nil {
						aggregatedSet[peer.IPBlock.CIDR] = struct{}{}
					}
				}
			}
		}
		// Convert aggregatedSet to a slice.
		aggregatedCIDRs := make([]string, 0, len(aggregatedSet))
		for cidr := range aggregatedSet {
			aggregatedCIDRs = append(aggregatedCIDRs, cidr)
		}
		// For each provided CIDR (comma-separated), create one object.
		cidrList := strings.Split(providedCIDRs, ",")
		for _, provided := range cidrList {
			providedTrim := strings.TrimSpace(provided)
			if providedTrim == "" {
				continue
			}
			// Parse the provided CIDR.
			_, providedNet, err := net.ParseCIDR(providedTrim)
			if err != nil {
				// Skip invalid provided CIDR.
				continue
			}
			// For each aggregated CIDR, if it is fully contained within the provided CIDR, add it.
			var contained []string
			for _, agg := range aggregatedCIDRs {
				_, aggNet, err := net.ParseCIDR(agg)
				if err != nil {
					continue
				}
				if cidrContained(aggNet, providedNet) {
					contained = append(contained, agg)
				}
			}
			object := DataCenterObject{
				Name:        providedTrim,
				ID:          uuid.NewSHA1(uuid.NameSpaceDNS, []byte(providedTrim)).String(),
				Description: "Aggregated network policy CIDRs contained in the provided CIDR",
				Ranges:      contained,
			}
			objects = append(objects, object)
		}

	default:
		// Default "all" view: aggregate all unique CIDRs across all NetworkPolicies.
		cidrSet := make(map[string]struct{})
		for _, np := range filteredPolicies {
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
