package aws_resource_vulnerabilities

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

// Internet exposure of EC2 instances, from Inspector's own NETWORK_REACHABILITY
// findings: Inspector analyzes route tables, network ACLs, security groups and
// load balancers and reports each open port with the full network path. A
// path that starts at an Internet gateway means the port is reachable from
// the Internet (VPN gateway / peering paths are not). Same
// inspector2:ListFindings permission the scan already has: no extra IAM.
//
// Only instances in the current coverage are asked about, so findings left
// behind by terminated instances (e.g. Karpenter churn) don't count.

const (
	// exposureWorkers keeps the extra queries light next to the main scan.
	exposureWorkers = 2
	// maxExposedPorts caps one instance's port list.
	maxExposedPorts = 20
	viaDirect       = "direct"
	viaLoadBalancer = "load balancer"
)

// ExposedPort is one port reachable from the Internet.
type ExposedPort struct {
	Protocol  string `json:"protocol"`
	PortBegin int32  `json:"port_begin"`
	PortEnd   int32  `json:"port_end"`
	// Via: "direct" (the instance itself, e.g. a public IP) or "load
	// balancer" (LoadBalancer names it, e.g. an EKS node port behind an NLB).
	Via            string `json:"via"`
	LoadBalancer   string `json:"load_balancer,omitempty"`
	InternetGW     string `json:"internet_gateway,omitempty"`
	LastObservedAt string `json:"last_observed_at,omitempty"`
}

// InternetExposure is an instance's Internet-reachable ports.
type InternetExposure struct {
	Direct     bool          `json:"direct"` // any port reachable without a load balancer
	Ports      []ExposedPort `json:"ports"`
	PortsTotal int           `json:"ports_total"`
}

// ExposedInstance is one covered instance with Internet-reachable ports,
// listed whether or not it has a vulnerability matching the request (an
// open SSH or Kubernetes API port is worth knowing on its own).
type ExposedInstance struct {
	ID              string        `json:"id"`
	Name            string        `json:"name,omitempty"`
	Direct          bool          `json:"direct"`
	Ports           []ExposedPort `json:"ports"`
	PortsTotal      int           `json:"ports_total"`
	Vulnerabilities int           `json:"vulnerabilities"` // matching the requested severities
}

// maxExposedInstances caps the report's exposed_instances list.
const maxExposedInstances = 200

// queryExposure collects Internet-reachable ports for every covered EC2
// instance, 10 instance IDs per call, on exposureWorkers goroutines.
func (s *scan) queryExposure(ctx context.Context) error {
	s.mu.Lock()
	ids := append([]string(nil), s.order...)
	s.mu.Unlock()
	sort.Strings(ids)
	next := make(chan []string)
	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		firstEr error
	)
	for w := 0; w < exposureWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for b := range next {
				if err := s.exposureBatch(ctx, b); err != nil {
					errOnce.Do(func() { firstEr = err })
				}
			}
		}()
	}
	for i := 0; i < len(ids) && ctx.Err() == nil; i += idsPerCall {
		next <- ids[i:min(i+idsPerCall, len(ids))]
	}
	close(next)
	wg.Wait()
	return firstEr
}

func (s *scan) exposureBatch(ctx context.Context, ids []string) error {
	fc := &itypes.FilterCriteria{
		FindingStatus: []itypes.StringFilter{eq("ACTIVE")},
		FindingType:   []itypes.StringFilter{eq("NETWORK_REACHABILITY")},
		ResourceType:  []itypes.StringFilter{eq(ResourceEC2)},
	}
	for _, id := range ids {
		fc.ResourceId = append(fc.ResourceId, eq(id))
	}
	var tok *string
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		out, err := s.insp.ListFindings(ctx, &inspector2.ListFindingsInput{FilterCriteria: fc, MaxResults: aws.Int32(100), NextToken: tok})
		if err != nil {
			return fmt.Errorf("inspector list network reachability findings: %w", err)
		}
		s.mu.Lock()
		for i := range out.Findings {
			s.addExposure(&out.Findings[i])
		}
		s.mu.Unlock()
		if aws.ToString(out.NextToken) == "" {
			return nil
		}
		tok = out.NextToken
	}
}

// addExposure records one NETWORK_REACHABILITY finding (mu held).
func (s *scan) addExposure(f *itypes.Finding) {
	port, ok := internetPort(f)
	if !ok || len(f.Resources) == 0 {
		return
	}
	id := aws.ToString(f.Resources[0].Id)
	e := s.exposure[id]
	if e == nil {
		e = &InternetExposure{}
		s.exposure[id] = e
	}
	e.PortsTotal++
	e.Direct = e.Direct || port.Via == viaDirect
	if len(e.Ports) < maxExposedPorts {
		e.Ports = append(e.Ports, port)
	}
}

// internetPort reads one NETWORK_REACHABILITY finding; ok only for a path
// that starts at an Internet gateway.
func internetPort(f *itypes.Finding) (ExposedPort, bool) {
	d := f.NetworkReachabilityDetails
	if d == nil || d.NetworkPath == nil || len(d.NetworkPath.Steps) == 0 {
		return ExposedPort{}, false
	}
	steps := d.NetworkPath.Steps
	if aws.ToString(steps[0].ComponentType) != "AWS::EC2::InternetGateway" {
		return ExposedPort{}, false
	}
	p := ExposedPort{Protocol: string(d.Protocol), Via: viaDirect, InternetGW: aws.ToString(steps[0].ComponentId)}
	if r := d.OpenPortRange; r != nil {
		p.PortBegin, p.PortEnd = aws.ToInt32(r.Begin), aws.ToInt32(r.End)
	}
	for _, st := range steps {
		if t := aws.ToString(st.ComponentType); strings.HasPrefix(t, "AWS::ElasticLoadBalancing") {
			p.Via, p.LoadBalancer = viaLoadBalancer, lbName(aws.ToString(st.ComponentId))
			break
		}
	}
	if f.LastObservedAt != nil {
		p.LastObservedAt = f.LastObservedAt.UTC().Format(time.RFC3339)
	}
	return p, true
}

// lbName extracts a load balancer's name from its ARN
// (.../loadbalancer/net/<name>/<id>, or .../loadbalancer/<name> for classic).
func lbName(arn string) string {
	parts := strings.Split(arn, "/")
	for i, p := range parts {
		if p == "net" || p == "app" || p == "gwy" {
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

// sortPorts: direct exposure first, then by port.
func sortPorts(ps []ExposedPort) {
	sort.SliceStable(ps, func(i, j int) bool {
		if (ps[i].Via == viaDirect) != (ps[j].Via == viaDirect) {
			return ps[i].Via == viaDirect
		}
		return ps[i].PortBegin < ps[j].PortBegin
	})
}
