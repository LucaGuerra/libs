# falcosecurity/libs with gVisor POC

This branch contains the necessary functionality to make the Falco libraries interact with the [gVisor Runtime Monitoring POC](https://github.com/google/gvisor/pull/7018).

## gVisor requirements

Runtime Monitoring POC https://github.com/google/gvisor/pull/7018 at commit bcb6da35c9ba9db292235656251c8c4e2585e6fb with the following patches:

* https://github.com/LucaGuerra/gvisor/commit/760e1a108e6b4b9e21002271acb38f684a7aeeb1
* https://github.com/LucaGuerra/gvisor/commit/75df2ab70bd4085bd156f009e149d05e15883b6e 
* https://github.com/LucaGuerra/gvisor/commit/a4b3593a417e3efd9489528e6394ac003150f2a2

Configure gVisor to use the provided configuration file in `./userspace/libscap/scap_gvisor/config.json`.

## Run with Falco

To build Falco, the procedure is the same as OSS Sysdig:

```
$ git clone https://github.com/LucaGuerra/libs.git
$ git clone https://github.com/LucaGuerra/falco.git
$ cd libs; git checkout gvisor-integration # or the specific commit ID
$ cd ../falco
$ git checkout gvisor
$ mkdir build; cd build
$ cmake -DFALCOSECURITY_LIBS_SOURCE_DIR=$(pwd)/../../libs -DUSE_BUNDLED_DEPS=On ..
$ make -j4
```

Then, you can run the demo ruleset _without UI_ from the build directory:

```
./userspace/falco/falco -c ../falco.yaml -r ../rules/gv.demo.yaml -g
```

or, if you wish to run the UI:
```
./userspace/falco/falco -c ../falco.ui.yaml -r ../rules/gv.demo.yaml -g
```

and the in another terminal run the following containers (locally on the host, without gvisor):

```
sudo docker run -e WEBUI_URL=http://localhost:2802 --net=host -d falcosecurity/falcosidekick
sudo docker run --net=host -d falcosecurity/falcosidekick-ui
```

And point your browser to http://localhost:2802/ui/ !

## Run with OSS Sysdig

Initially, this can be easily tested with [OSS Sysdig](https://github.com/draios/sysdig) to display events as explained in the instructions below. The plan of course involves making this fully compatible with Falco.

To build this version, check out both this repo on this branch/commit and OSS Sysdig
```
$ git clone https://github.com/LucaGuerra/libs.git
$ git clone https://github.com/draios/sysdig.git
$ cd libs; git checkout gvisor-integration # or the specific commit ID
$ cd ../sysdig
$ git checkout gvisor
$ mkdir build; cd build
$ cmake -DFALCOSECURITY_LIBS_SOURCE_DIR=$(pwd)/../../libs -DUSE_BUNDLED_DEPS=On ..
$ make -j4
```

and then run
```
./userspace/sysdig/sysdig -g
```

The socket is currently hardcoded as `/tmp/123.sock` because it was so written in the gVisor POC but that will change in the future.

As an example, with this sample gVisor configuration
```
{
  "name": "Default",
  "points": [{
    "name": "container/start"
  }, {
    "name": "syscall/openat/enter",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/openat/exit",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
   }, {
    "name": "syscall/read/enter",
    "optional_fields": [ "fd_path" ],
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/read/exit",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/1/enter",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/1/exit",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/connect/enter",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }, {
    "name": "syscall/connect/exit",
    "context_fields": [ "credentials", "container_id", "thread_id", "task_start_time" ]
  }],
  "sinks": [{
    "name": "remote",
    "config": {
      "endpoint": "/tmp/123.sock"
    }
  }]
}
```

We can then run a sandbox
```
sudo docker run -it --runtime=runsc ubuntu bash
```

And see the results in real time in the sysdig console.

Below you can find the original `falcosecurity/libs` readme.

# falcosecurity/libs

As per the [OSS Libraries Contribution Plan](https://github.com/falcosecurity/falco/blob/master/proposals/20210119-libraries-contribution.md), this repository has been chosen to be the new home for **libsinsp**, **libscap**, the **kernel module** and the **eBPF probe** sources.  
Refer to https://falco.org/blog/contribution-drivers-kmod-ebpf-libraries/ for more informations.  

These components are at the foundation of [Falco](https://github.com/falcosecurity/falco) and other projects that work with the same kind of data.

This component stack mainly operates on a data source: system calls. This data source is collected using either a kernel module or an eBPF probe, which we call *drivers*. On top of the drivers, libscap manages the data capture process, libsinsp enriches the data, and provides a rich set of API to consume the data. Furthermore, these two libraries also implement a [plugin](https://github.com/falcosecurity/plugins) framework that extends this stack to potentially any other data sources.

An image is worth a thousand words, they say:

![diagram](https://falco.org/img/falco-diagram-blog-contribution.png)

## Project Layout

* [_driver/_](./driver) contains kernel module and eBPF probe source code,
so-called **drivers**.       
* [_userspace/_](./userspace) contains libscap and libsinsp libraries code,
plus chisels related code and common utilities.
  * **libscap** (aka lib for *System CAPture*) is the userspace library
  that directly communicates with the drivers, reading syscall events from
  the ring buffer (where drivers place them), and forwarding them
  up to libsinsp. Moreover, libscap implements OS state collection and
  supports reading/writing to scap files.  
  * **libsinsp** (aka lib for *System INSPection*) receives events from
  libscap and enriches them with machine state: moreover, it performs
  events filtering with rule evaluation through its internal rule engine.
  Finally, it manages outputs. 
  * **chisels** are just little Lua scripts to analyze an event stream
  and perform useful actions. In this subfolder, the backend code for
  chisels support can be found.  
* [_proposals/_](./proposals) unexpectedly contains the list of proposals.
* [_cmake/modules/_](./cmake/modules) contains modules to build
external dependencies, plus the libscap and libsinsp ones; consumers
(like Falco) use those modules to build the libs in their projects.

## Build

Libs relies upon `cmake` build system.  
Lots of `make` targets will be available; the most important ones are:
* `driver` -> to build the kmod
* `bpf` -> to build the eBPF probe
* `scap` -> to build libscap
* `sinsp` -> to build libsinsp (depends upon `scap` target)
* `scap-open` -> to build a small libscap example to quickly test drivers (depends upon `scap`)

To start, first create and move inside `build/` folder:
```bash
mkdir build && cd build
```

### Bundled deps

Easiest way to build the project is to use BUNDLED_DEPS option, 
meaning that most of the dependencies will be fetched and compiled during the process:
```bash
cmake -DUSE_BUNDLED_DEPS=true ../
make sinsp
```
> **NOTE:** take a break as this will take quite a bit of time (around 15 mins, dependent on the hardware obviously).

### System deps

To build using the system deps instead, first make sure to have all the needed packages installed.  
Refer to https://falco.org/docs/getting-started/source/ for the list of dependencies.  

Then, simply issue:
```bash
cmake ../
make sinsp
```

> **NOTE:** using system libraries is useful to cut compile times down, as this way it will only build libs, and not all deps.  
> On the other hand, system deps version may have an impact, and we cannot guarantee everything goes smoothly while using them.

### Build kmod

To build the kmod driver, you need your kernel headers installed. Again, checkout the Falco documentation for this step.  
Then it will be just a matter of running:
```bash
make driver
```

### Build eBPF probe

To build the eBPF probe, you need `clang` and `llvm` packages.  
Then, issue:
```bash
cmake -DBUILD_BPF=true ../
make bpf
```

## Test drivers

Libscap ships a small example that is quite handy to quickly check that drivers are working fine.  
To build it, issue:
```bash
make scap-open
```

Then, to execute it with the eBPF probe, issue:
```bash
sudo BPF_PROBE=driver/bpf/probe.o ./libscap/examples/01-open/scap-open
```

To execute it with the kmod instead issue:
```bash
sudo insmod driver/scap.ko
sudo ./libscap/examples/01-open/scap-open
sudo rmmod scap
```

As soon as you quit (ctrl-C) the scap-open program, you will be prompted with detailed informations on the capture:
```bash
events captured: 39460
seen by driver: 39912
Number of dropped events: 0
Number of dropped events caused by full buffer: 0
Number of dropped events caused by invalid memory access: 0
Number of dropped events caused by an invalid condition in the kernel instrumentation: 0
Number of preemptions: 0
Number of events skipped due to the tid being in a set of suppressed tids: 0
Number of threads currently being suppressed: 0
```
therefore confirming that the drivers are indeed working fine! 

## Contribute

Any contribution is incredibly helpful and **warmly** accepted; be it code, documentation, or just ideas, please feel free to share it!  
For a contribution guideline, refer to: https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md.

### Adding syscalls

Implementing new syscalls is surely one of the highest frequency request.  
While it is indeed important for libs to support as many syscalls as possible, most of the time it is not a high priority task.  
But **you** can speed up things by opening a PR for it!  
Luckily enough, a Falco blog post explains the process very thoroughly: https://falco.org/blog/falco-monitoring-new-syscalls/.

## License

This project is licensed to you under the [Apache 2.0](./COPYING) open source license. Some subcomponents might be licensed separately. You can find licensing notices [here](./NOTICES).  