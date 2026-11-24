package api

import (
	"testing"

	v1 "k8s.io/api/networking/v1"
)

func TestIsAnyCIDR(t *testing.T) {
	tests := map[string]bool{
		"0.0.0.0/0":     true,
		"::/0":          true,
		"0::0/0":        true,
		"0.0.0.0/8":     false,
		"10.0.0.0/8":    false,
		"2001:db8::/32": false,
		"invalid":       false,
	}
	for cidr, want := range tests {
		if got := isAnyCIDR(cidr); got != want {
			t.Errorf("isAnyCIDR(%q) = %v, want %v", cidr, got, want)
		}
	}
}

func TestAddEgressCIDRsSkipsMatchAll(t *testing.T) {
	np := v1.NetworkPolicy{}
	np.Spec.Egress = []v1.NetworkPolicyEgressRule{{
		To: []v1.NetworkPolicyPeer{
			{IPBlock: &v1.IPBlock{CIDR: "0.0.0.0/0"}},
			{IPBlock: &v1.IPBlock{CIDR: "::/0"}},
			{IPBlock: &v1.IPBlock{CIDR: "203.0.113.0/24"}},
		},
	}}
	set := map[string]struct{}{}
	addEgressCIDRs(set, np)
	if _, ok := set["203.0.113.0/24"]; !ok || len(set) != 1 {
		t.Errorf("unexpected set: %v", set)
	}
}
