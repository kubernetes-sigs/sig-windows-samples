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
