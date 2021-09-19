Filter packets sent/received within a cgroup

Define a cgroup:
```
mkdir /sys/fs/cgroup/test
```
Attach the eBPF:
```
sudo ./cmd/load/load -cgroup /sys/fs/cgroup/test
```
In another terminal enter the cgroup:
```
sudo apt install cgroup-tools
cgexec -g *:/sys/fs/cgroup/test bash
ping 8.8.8.8
```
In another terminal block the traffic:
```
sudo ./cmd/block/block 8.8.8.8
```
