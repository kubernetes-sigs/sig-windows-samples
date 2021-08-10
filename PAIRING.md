# Sig windows pairing/hacking notes

## 3/9/2021

### https://github.com/kubernetes/kubernetes/pull/96616/files
- what is this !? 
```
		if "S-1-5-32-544" == ids[i] {
```
- https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab
- 

### kube proxy for windows

- ipvs, iptables, userspace
- regular, userspace : 
    - hns, vfp loadbalancers etc, iptables replacement for windwos
-https://github.com/kubernetes-sigs/sig-windows-tools/tree/master/kubeadm/kube-proxy
    - burrito pods
- https://github.com/kubernetes/kubernetes/pull/97238/files pretty complex endpoint terminating kube proxy mods we need to look at , at some point

### multi-arch images, cni startup for antrea

#### antrea
- https://www.techcrumble.net/2019/11/vmware-open-source-kubernetes-networking-project-antrea/
- calico: host-local ipam + route tables + vxlan vs ovs 

#### multi arch docker images

- https://perithompson.netlify.app/blog/creating-multiarch-containers/
- oci spec
    - manifest list
        - individual components
    - buildx
        - ONLY WORKS FOR
            - adding files (i.e. `pause`)
            - ENTRYPOINT
        - pulls down FS
        - copies binaries -> image
        - no extract    
        - NO RUN COMMANDS
            - sonobuoy example
                - BUild on the host
                - package in buildx
        - registry writes fail OPEN
     - See
         - https://github.com/kubernetes/kubernetes/blob/master/test/images/busybox/Dockerfile_windows#L86
         - https://github.com/kubernetes/kubernetes/tree/master/test/images#windows-test-images-considerations
     - OMG
         - pushd/popd work on windows
     - # 2019 + windows versions
       - LTSC
           - 2019 (= 1809)
           - 1809
       - SAC (18 mo)
           - 1903 
           - 20H2 
           - 1909 
           - 2004
           - 
#### image-builder + friedrich's project update

- Freidrich
    - https://github.com/kubernetes-sigs/sig-windows-tools/issues/145
    - https://github.com/kubernetes-sigs/sig-windows-tools/blob/master/kubeadm/scripts/PrepareNode.ps1 <- cni agnostic
- https://docs.projectcalico.org/getting-started/windows-calico/kubernetes/standard
    - containerd 
        - kubelet needs CNI to start init pods
        - antrea broke the NAT network
    - images/packer/capi/ova/windows
        - has image builder logic for creating ova
        - friedrichs project ~ likely will live bootstrap unless a good reason to use img builder
        - NExt step ~ vagrant ps1 commands
    - https://github.com/vmware-tanzu/antrea/pull/1968 <- antrea containerd docs

#### image builder part 2 + friedrichs project updates
- powershell via a makefile is triggering vagrant stuff
- triage
    - https://github.com/kubernetes/kubernetes/issues/82532 <-- james azure (move to project boardthingy)
    - https://github.com/kubernetes/kubernetes/issues/93945 <-- iis 10mb, seems like a non issue, weird use case
    - https://github.com/kubernetes/kubernetes/issues/100384 <-- critical kube proxy bug ELBs
    - https://github.com/kubernetes/kubernetes/issues/96428 <-- os bug that mark is working on
    - https://github.com/kubernetes/kubernetes/issues/96935 <-- ravi working on it, need to ping
    - https://github.com/kubernetes/kubernetes/issues/96996 <-- kayla , flannel non-nodeipam issue low prio, why not use nodeipam? 
    - https://github.com/kubernetes/kubernetes/issues/98102 -> https://github.com/containerd/containerd/issues/5188
    - 

#### 4/13
    - rancher is here ! hayden ~ liason w/ sig-security
    - friedrich + Slaydn teaming up on windows dev environments
    - SourceVip
        - friedrich/sladyn ~ sourcevip command fails, workaround https://gist.github.com/rosskirkpat/063416fdf5512adc99fab85a411f7947 
        - webhook tests fail w/ it 
    - https://github.com/FriedrichWilken/KubernetesOnWindows/issues/3
    - hayden barnes is a General Hospital character
    - https://github.com/kubernetes/kubernetes/issues/101062
    - https://github.com/kubernetes/website/pull/12182
```
       300 conformance tests

       test: pod1 ---->  hostport pod2
       test: pod1 ---->  nodeport -> pod2
       test: pod1 ---->  clusterip -> pod2
       
        SUCCESS

            n1 n2 n3 n4 n5
            p1 
            p2

        FAIL

            n1 n2 n3 n4 n5
               p1 
            p2
```
#### 4/20
- cbr0: the way flannel defines host bridges
- sdn_overlay vs win-overlay : cni executable, 2 sources of truth 
- cni config json (windows):
    - plugin:
        - docker
            - docker nat
                - kube proxy
                - ...            
            - overlay
                - main plugin (winbridge, winoverlay)
                - metaplugin (flannel) 
        - containerd
            - overlay
- https://www.cni.dev/plugins/current/main/win-overlay/
- https://www.cni.dev/plugins/current/meta/flannel/
- https://gist.github.com/rosskirkpat/568b6b8ad8c5083d0dfec5c46628c453
- bare minimal flannel -> NeedEncap=true (hns) for overlays + note 10./ is encap.
```
{
	"name": "vxlan0",
	"type": "flannel",
	"ipMasq": true,
	"ipam": {
		"type": "host-local",
		"subnet": "10.42.2.0/24"
	},       
    "capabilites": {
        "dns": true
    },    
	"delegate": {
		"type": "win-overlay"
    },
    "Policies" : [
        {
          "Name" : "EndpointPolicy", "Value" : { "Type" : "OutBoundNAT", "ExceptionList": [ "10.42.0.0/16","10.43.0.0/16" ] }
        },
        {
          "Name" : "EndpointPolicy", "Value" : { "Type" : "ROUTE", "DestinationPrefix": "10.0.0.0/8", "NeedEncap" : true }
        }
      ]    
}
```
- next time , need to dig around on more CNI stuff 

## 5/4

- updating dev environments to use containerd.
- Running the containerd.ps1 script twice    
- -FeatureName Micosoft Hper-V Management -PowerShell
- CPU silently crashing in background

### signal

https://testgrid.k8s.io/
https://testgrid.k8s.io/sig-windows-signal
(testgrid bug , status not up to date)

### finding a flake source... 

- https://github.com/kubernetes/kubernetes/blob/9126048c9c47cc51f15f977da51c6023229a02b5/test/e2e/common/node/container_probe.go#L659

- to learn more, check out flakey fridays (youtube)
- worth looking at this https://github.com/kubernetes/community/blob/master/contributors/devel/sig-testing/flaky-tests.md#deflaking-e2e-tests 

- sig-windows log scraping: pdsh style collector

https://github.com/kubernetes-sigs/windows-testing/blob/master/scripts/win-ci-logs-collector.sh

- https://github.com/kubernetes-sigs/cluster-api-provider-azure/pull/1351/files 

# 5/11

- flannel , containerd on windows
    - need to run as an agent (no Docker NAT network available, thus no hostNet pods to bootstrap)
    - containerd host pods:
        - cni pods fail b/c "hostNetwork" docker hack doesnt work
        - containerd can't bootsrap cni pods, chicken or egg
        - solution: check sandbox for hostProcess
            - if hostProcess + windows -> create pod
                - because containerd knows how to put stuff on hostNetwork!
        - https://github.com/containerd/containerd/pull/5131/files
    - old GCE Kubeadm job
        - unmaintained ~ replacement for it?
    - how to NSSM a CNI provider?
        - https://github.com/vmware-tanzu/antrea/blob/main/docs/windows.md 
- @slayden might want to try hot swapping the kubelet binary / kube proxy binary
        - https://github.com/kubernetes/community/blob/master/sig-windows/CONTRIBUTING.md#building-kubernetes-binaries-for-windows

# 5/15

- james: https://github.com/kubernetes-sigs/windows-gmsa/pull/31 
    - v1beta1 -> v1 for GMSA in 1.22 needed to be upgraded
    - but for cert-request `kind: CertificateSigningRequest` sig-auth, couldnt easily craft the request to work with the new apiVersion
- slayden: dynamic compilation of kubelet.exe and kube-proxy exe into dev environments https://github.com/FriedrichWilken/KubernetesOnWindows
- Self-registering antrea service https://github.com/antrea-io/antrea/issues/2187 ! might be a good hack project for someone interested in CNIs.
    - https://github.com/antrea-io/antrea/blob/main/docs/windows.md#installation-as-a-service-containerd-based-runtimes 

# 5/25

- friedrich is recovering from his injury
- How windows vs linux objects coexist in golang
    - https://github.com/kubernetes/kubernetes/tree/master/cmd/kube-proxy/app
    - https://github.com/antrea-io/antrea/cmd/antrea-agent/options.go
    - https://billg.sqlteam.com/2018/07/17/running-go-as-a-windows-service/
    - https://github.com/golang/sys/blob/master/windows/svc/example/service.go
    - https://github.com/judwhite/go-svc
- community repo on the way https://github.com/kubernetes/org/issues/2721
- GMSA how its setup
    - webhook makes it easy to run pods that reference GMSA CRDs
        - https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster <-- prerequisite for understanding the GMSA flow
        - file = output file.. `curl -sL  k8s.io/..../deploy-gmsa-webhook.sh | bash -s -- --file webhook-manifests.yml`
            - deploy-gmsa-webhook.sh
                - create-signed-cert.sh <-- good to try to read understand this 
                    - apiserver signs
            - But why do we need a k8s webhook for the kubelet?
                - json serialize -> kubelet pulls it -> pod spec
                - webhook makes it easy to define the JSON as a k8s CRD
                    - when pod matches the GMSA in a CRD, webhook modifies pod to integrate the CRD
    - example of how to look at a windows flake
        - https://prow.k8s.io/view/gs/kubernetes-jenkins/logs/ci-kubernetes-e2e-aks-engine-azure-1-20-windows-containerd/1396143134877945856
            - https://github.com/kubernetes/kubernetes/blob/master/test/e2e/apimachinery/crd_publish_openapi.go#L66 
                - interesting test - confirms `kubectl` behaviour validity for CRDs
    - grep.app
    - claudio:
        - liveness probes, readiness probes for windows nodes
        - pre-stop post-start exec hooks dont work on flannel overlay
            - windows overlay dont allow nodes -> pod connectivity

# 6/1 

- james AD testing
    - gmsa_kubelet.go
        - NLTest `/parentdomain` making sure that kubelet returns stuff
    - gmsa_full.go
        - full on gmsa test that involves confirming that the ability (generate correct  GMSA CRDs and push them)
    - GMSA Component installation
- peri ~ NetLOGON: 
    - a folder thats on every AD controller, contains group policies + files 
    - AD Controller = windows server playing AD controller role
- ks/windows-testing
    - gmsa-dc : turn node into dc
    - gmsa-member: join a node to a domai
      - outputs: 
          - admin.txt
          - gmsa-cred-spec-gmsa-e2e.txt
- windows-gmsa/
    - james modernizing it
        - use newer go cli


# 6/8
- Windows dev environment hacking 
    - official dev env : code complete , 
        - waiting on Friedrich's CLA
    - Why does windows have 2 ETH adaptors 
    ```Ethernet adapter Ethernet:
    
# 6/22
How to pull the ci/ staging images.... 
- https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/master/templates/test/dev/custom-builds/patches/custom-builds.yaml 
- USE THIS ! to run kubeadm at the tip .... 
```

func TestSplitVersion(t *testing.T) {
	type T struct {
		input  string
		bucket string
		label  string
		valid  bool
	}
	cases := []T{
		// Release area
		{"ci/latest", "https://storage.googleapis.com/k8s-release-dev/ci", "latest", true},
        ...
	}
```

       Connection-specific DNS Suffix  . : 
       Link-local IPv6 Address . . . . . : fe80::6cb5:fdde:294b:118b%4
       IPv4 Address. . . . . . . . . . . : 10.0.2.15
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 10.0.2.2

    Ethernet adapter Ethernet 2:

       Connection-specific DNS Suffix  . : 
       Link-local IPv6 Address . . . . . : fe80::4019:f73d:2675:fa51%7
       IPv4 Address. . . . . . . . . . . : 10.20.30.11
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 
    ```
    - https://github.com/kubernetes-sigs/cluster-api-provider-azure/blob/d31799bf430454983ed426b482610ad9d080840c/templates/flavors/ipv6/patches/kubeadm-controlplane.yaml
    - Node Problem Detector: running it in windows outside of GCE.  Maybe a good use case for the dev recipes.
    
    
# 7/13

Windows-dev environments:
- calico issue , wonder if its VNIC related, https://github.com/containerd/containerd/issues/5729 
- compiling k8s on WSL2 for dev envs
- if anyone is crazy enough to run windows server on a laptop heres how https://jayunit100.blogspot.com/2021/03/connecting-my-dell-precision-5540-on.html 
- james once got containerd working on windows 10, but that doesnt work anymore bc of 21H1... :( 
- `winw1: Download file, try ( 1 )  [[[ https://k8stestinfrabinaries.blob.core.windows.net/nssm-mirror/nssm-2.24.zip ]]]`
- in 1.23, bunch of changes coming for `hostProcess` containers, which will modify the install-containerd.ps1 and preparenode.ps1 files.
- defining hyper-v addresses in vagrant is ignored.  need to decide wether virtualbox->hyperv, hyperv, or vmware workstation is the ideal solution for windows laptops
- added vagrant/robox as the linux base image bc its compatible w/ all hypervisors
- `    winw1: Waiting for Calico initialisation to finish...StoredLastBootTime , CurrentLastBootTime 20210713111004.900955-420` <-- calico windows seems to slow down at this stage, but not sure why... 

# 7/20 

- Bart demo'd that hes having issues around anonymous permissions / network login in terms of browsing directories
  - powershell exectution policies C:/forked/Install-Containerd.ps1

# 7/27

- filed https://github.com/kubernetes-sigs/sig-windows-dev-tools/issues/64 to investigate pause image 
- starting calico felix seems to get CNI working but vagrant hangs... 

# 8/10

- How pause images work : is the "infra" pause container somehow, or somewhere, referenced in the OCI specification ? 
- Why does friedrich not have a route to a pod network on his VM ? https://github.com/kubernetes-sigs/sig-windows-dev-tools/issues/73 ...
maybe because its in the `notReady` state ? Check calico and kube proxy logs...
	- linux node up
	- calico (node + felix) on linux up
	- linux node is "ready"
	- windows node up
	- windows node joins cluster <--- this is where you are friedrich !
	- calico node on windows installed 
	- calico felix on windows is installed 
	- calico node is "ready"
	- calico routes are broadcast to linux node

