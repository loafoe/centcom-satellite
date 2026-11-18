package aws_resource_vulnerabilities

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	itypes "github.com/aws/aws-sdk-go-v2/service/inspector2/types"
)

func reach(instance, firstHop string, port int32, viaLB string) itypes.Finding {
	steps := []itypes.Step{{ComponentType: aws.String(firstHop), ComponentId: aws.String("igw-1")}, {ComponentType: aws.String("AWS::EC2::SecurityGroup")}}
	if viaLB != "" {
		steps = append(steps, itypes.Step{ComponentType: aws.String("AWS::ElasticLoadBalancingV2::LoadBalancer"),
			ComponentId: aws.String("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/" + viaLB + "/abc")})
	}
	steps = append(steps, itypes.Step{ComponentType: aws.String("AWS::EC2::Instance"), ComponentId: aws.String(instance)})
	return itypes.Finding{
		Type: itypes.FindingTypeNetworkReachability, LastObservedAt: aws.Time(time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)),
		Resources: []itypes.Resource{{Id: aws.String(instance), Type: itypes.ResourceTypeAwsEc2Instance}},
		NetworkReachabilityDetails: &itypes.NetworkReachabilityDetails{
			Protocol: itypes.NetworkProtocolTcp, OpenPortRange: &itypes.PortRange{Begin: aws.Int32(port), End: aws.Int32(port)},
			NetworkPath: &itypes.NetworkPath{Steps: steps},
		},
	}
}

func TestExecute_InternetExposureFromNetworkReachability(t *testing.T) {
	fake := &fakeInspector{
		covered: []itypes.CoveredResource{ec2Coverage("i-bastion", "bastion", "ACTIVE"), ec2Coverage("i-node", "eks-node", "ACTIVE"), ec2Coverage("i-vpn", "vpn-only", "ACTIVE"),
			ec2Coverage("i-api", "k3s-master", "ACTIVE")}, // open port, no matching CVEs
		findings: []itypes.Finding{
			pkgFinding("i-bastion", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-vpn", "CVE-A", itypes.SeverityCritical, 9.8, itypes.FixAvailableYes),
			pkgFinding("i-node", "CVE-B", itypes.SeverityCritical, 9.1, itypes.FixAvailableNo),
		},
		reachability: []itypes.Finding{
			reach("i-bastion", "AWS::EC2::InternetGateway", 22, ""),
			reach("i-node", "AWS::EC2::InternetGateway", 30684, "platform-gateway"),
			reach("i-vpn", "AWS::EC2::VPNGateway", 443, ""),      // not the Internet
			reach("i-gone", "AWS::EC2::InternetGateway", 22, ""), // terminated: not in coverage
			reach("i-api", "AWS::EC2::InternetGateway", 6443, ""),
		},
	}
	r := run(t, fake, `{"resource_type":"EC2"}`, time.Minute)
	if !r.ExposureChecked || r.InternetExposedResources != 3 {
		t.Fatalf("exposure_checked=%v internet_exposed_resources=%d, want true/3", r.ExposureChecked, r.InternetExposedResources)
	}
	byID := map[string]ExposedInstance{}
	for _, x := range r.ExposedInstances {
		byID[x.ID] = x
	}
	if api := byID["i-api"]; !api.Direct || api.Ports[0].PortBegin != 6443 || api.Vulnerabilities != 0 || api.Name != "k3s-master" {
		t.Fatalf("an exposed instance without matching CVEs must still be listed: %+v", api)
	}
	if !r.ExposedInstances[0].Direct || r.ExposedInstances[len(r.ExposedInstances)-1].Direct {
		t.Fatalf("direct exposure first: %+v", r.ExposedInstances)
	}
	res := map[string]Resource{}
	for _, x := range r.Resources {
		res[x.ID] = x
	}
	if e := res["i-bastion"].InternetExposure; e == nil || !e.Direct || e.Ports[0].PortBegin != 22 || e.Ports[0].Via != viaDirect {
		t.Fatalf("bastion: %+v", e)
	}
	if e := res["i-node"].InternetExposure; e == nil || e.Direct || e.Ports[0].Via != viaLoadBalancer || e.Ports[0].LoadBalancer != "platform-gateway" {
		t.Fatalf("node behind the NLB: %+v", e)
	}
	if res["i-vpn"].InternetExposure != nil {
		t.Fatal("a VPN-gateway path is not Internet exposure")
	}
	for _, v := range r.Vulnerabilities {
		if v.ID == "CVE-A" && (v.ExposedResourcesTotal != 1 || v.ExposedResources[0] != "i-bastion") {
			t.Fatalf("CVE-A exposed resources: %+v", v.ExposedResources)
		}
	}
}

func TestExecute_NoExposureLookupForLambdaOrWhenSkipped(t *testing.T) {
	fake := &fakeInspector{covered: []itypes.CoveredResource{ec2Coverage("i-1", "a", "ACTIVE")}, reachability: []itypes.Finding{reach("i-1", "AWS::EC2::InternetGateway", 22, "")}}
	if r := run(t, fake, `{"resource_type":"EC2","skip_exposure":true}`, time.Minute); r.ExposureChecked || r.InternetExposedResources != 0 {
		t.Fatalf("skip_exposure: %+v", r)
	}
	if got := lbName("arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/net/ep-dev-us-gateway/0a69"); got != "ep-dev-us-gateway" {
		t.Fatalf("lbName = %q", got)
	}
}
