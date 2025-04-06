package api

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"

	"github.com/google/uuid"
	v1 "k8s.io/api/networking/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Global variable for gitops tracking requirement, read from environment.
var requiredTracking string

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
	requiredTracking = os.Getenv("GITOPS_TRACKING_REQUIREMENT")
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

// lastIP calculates the last IPv4 address in the given IPNet.
func lastIP(n *net.IPNet) net.IP {
	ip := n.IP.To4()
	if ip == nil {
		// Fallback to original IP if not IPv4.
		return n.IP
	}
	mask := n.Mask
	ipInt := binary.BigEndian.Uint32(ip)
	maskInt := binary.BigEndian.Uint32(mask)
	lastInt := ipInt | ^maskInt
	lastIP := make([]byte, 4)
	binary.BigEndian.PutUint32(lastIP, lastInt)
	return net.IP(lastIP)
}

// passesGitopsTracking returns true if the network policy meets the gitops tracking requirement.
func passesGitopsTracking(np v1.NetworkPolicy) bool {
	switch requiredTracking {
	case "label":
		if val, ok := np.Labels["app.kubernetes.io/instance"]; ok && val != "" {
			return true
		}
		return false
	case "annotation":
		if val, ok := np.Annotations["argocd.argoproj.io/tracking-id"]; ok && val != "" {
			return true
		}
		return false
	case "label+annotation":
		if val, ok := np.Labels["app.kubernetes.io/instance"]; ok && val != "" {
			if val2, ok := np.Annotations["argocd.argoproj.io/tracking-id"]; ok && val2 != "" {
				return true
			}
		}
		return false
	default:
		// No filtering if the env variable is not set or is an unrecognized value.
		return true
	}
}

// Custom type to sort CIDRs by their IP address.
type cidrSlice []string

func (c cidrSlice) Len() int      { return len(c) }
func (c cidrSlice) Swap(i, j int) { c[i], c[j] = c[j], c[i] }
func (c cidrSlice) Less(i, j int) bool {
	_, ipnet1, err1 := net.ParseCIDR(c[i])
	_, ipnet2, err2 := net.ParseCIDR(c[j])
	if err1 != nil || err2 != nil {
		return c[i] < c[j]
	}
	return bytes.Compare(ipnet1.IP, ipnet2.IP) < 0
}

// GetNetworkPolicyEgressCIDRs returns a JSON string formatted per the selected view:
// - "all" (default): one aggregated object of all unique CIDRs;
// - "policy": one object per NetworkPolicy;
// - "namespace": one object per namespace;
// - "internet": two objects (public and private aggregated separately);
// - "cidr": one object per user-provided CIDR, where each object's Ranges includes only those aggregated network policy CIDRs that are fully contained within the provided CIDR.
// The filterNamespace and filterName parameters are optional; if empty, no filtering is applied for those fields.
// Additionally, the function filters network policies based on the gitops tracking requirement.
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

	// Filter policies based on gitops tracking requirement and optional namespace/name filters.
	var filteredPolicies []v1.NetworkPolicy
	for _, np := range networkPolicyList.Items {
		if !passesGitopsTracking(np) {
			continue
		}
		if filterNamespace != "" && np.Namespace != filterNamespace {
			continue
		}
		if filterName != "" && np.Name != filterName {
			continue
		}
		filteredPolicies = append(filteredPolicies, np)
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
			sort.Sort(cidrSlice(cidrs))
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
			sort.Sort(cidrSlice(cidrs))
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
		sort.Sort(cidrSlice(publicCIDRs))
		sort.Sort(cidrSlice(privateCIDRsList))
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
		sort.Sort(cidrSlice(aggregatedCIDRs))
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
			sort.Sort(cidrSlice(contained))
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
		sort.Sort(cidrSlice(cidrs))
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
