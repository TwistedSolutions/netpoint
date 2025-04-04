# NetPoint

NetPoint is a Kubernetes network policy exporter built to transform NetworkPolicy data into a format that Checkpoint firewalls can consume. The application aggregates and filters NetworkPolicies across your cluster and exports them as DataCenterObjects. It supports multiple views, GitOps tracking requirements.

## Features

- **Export for Checkpoint Firewalls:**  
  Exports NetworkPolicies in a DataCenterObject JSON format that can be directly imported into Checkpoint firewall environments.

- **Multiple Views:**  
  - **all:** Aggregates all unique CIDRs across all NetworkPolicies into a single object.  
  - **policy:** Returns one DataCenterObject per individual NetworkPolicy.  
  - **namespace:** Groups NetworkPolicies by namespace, aggregating CIDRs per namespace.  
  - **internet:** Separates aggregated CIDRs into two objects – one for public and one for private addresses.  
  - **cidr:** Accepts a comma‑separated list of CIDRs and creates one DataCenterObject per provided CIDR, including only those network policy CIDRs that fall within the provided range.

- **GitOps Tracking Enforcement:**  
  The application can enforce a GitOps tracking requirement via an environment variable (`GITOPS_TRACKING_REQUIREMENT`):
  - `label`: Only NetworkPolicies with the `app.kubernetes.io/instance` label are included.
  - `annotation`: Only NetworkPolicies with the `argocd.argoproj.io/tracking-id` annotation are included.
  - `label+annotation`: Both the label and the annotation must be present.
  - (Unset or any other value): No GitOps tracking filtering is applied.

## License

Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.