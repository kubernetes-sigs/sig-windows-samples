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
    - SourceVip ~ overlay CNI providers ~ need updated SDN version thanks to rancher for providing it to friedrich
        - friedrich/sladyn ~ sourcevip command fails, workaround https://gist.github.com/rosskirkpat/063416fdf5512adc99fab85a411f7947 
        - webhook tests fail w/ it 
    - https://github.com/FriedrichWilken/KubernetesOnWindows/issues/3
    - hayden barnes is a General Hospital character
    - https://github.com/kubernetes/kubernetes/issues/101062
    - https://github.com/kubernetes/website/pull/12182
    - friedrich's project graduates from 'learning' to USEFUL !
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
    
    


