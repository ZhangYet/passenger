# Kubernetes Q&A

## 1. 用户提交的到底是什么？

Q: YAML 如何对应 API 对象？

A: YAML 是 API 对象的一种文本表示。通过 kubectl 提交 YAML 配置时，kubectl 将配置转换成 API 请求，由 API Server 处理并创建或更新对象。

用户提交的配置通常包含 apiVersion、kind、metadata 和期望配置；对于 Pod、Deployment 等资源，期望配置位于 spec。status 通常由系统组件维护，创建资源时一般不填写。读取已有对象时，返回的 YAML 可以包含 status。并非所有资源都有 spec/status，例如 ConfigMap 使用 data 等字段。

文档：[Describing a Kubernetes object](https://kubernetes.io/docs/concepts/overview/working-with-objects/#describing-a-kubernetes-object)、[Object spec and status](https://kubernetes.io/docs/concepts/overview/working-with-objects/#object-spec-and-status)。

Q: apiVersion、kind、metadata、spec、status 分别表示什么？

A:

1. apiVersion：对象使用的 API 组及版本，例如 apps/v1；核心组写作 v1。
2. kind：对象的类型，例如 Deployment、Pod。
3. metadata：对象的元数据，包括 name、namespace（对命名空间级资源）、服务端生成的 UID，以及 labels、annotations 等。
4. spec：期望状态，例如期望副本数、容器镜像。
5. status：相关组件最近观察并报告的状态。它可能落后于此刻的实际情况，例如节点刚断电时，API 中的状态尚未更新。

文档：[Required fields](https://kubernetes.io/docs/concepts/overview/working-with-objects/#required-fields)、[Object spec and status](https://kubernetes.io/docs/concepts/overview/working-with-objects/#object-spec-and-status)。

Q: 期望状态和实际状态有什么区别，分别由谁更新？

A: spec 描述希望系统达到的状态，可以由用户或控制器更新。实际状态是系统此刻真正的运行情况；相关组件执行协调操作，并将观察结果报告到 status。例如用户希望运行 3 个副本，但目前可能只有 2 个就绪副本。

系统组件是“观察并报告”实际状态，而不是任意决定实际状态；进程崩溃、网络故障等都会影响现实。spec 也不只由用户修改，例如上层控制器可以创建和更新下层资源的期望配置。

文档：[Object spec and status](https://kubernetes.io/docs/concepts/overview/working-with-objects/#object-spec-and-status)、[Controllers — Control via API server](https://kubernetes.io/docs/concepts/architecture/controller/#control-via-api-server)。

Q: 创建一个 Node 对象，与创建一台机器有什么区别？

A: Node 对象是机器在 Kubernetes 中的记录。创建机器意味着准备实际的物理机或虚拟机，具有 CPU、内存和操作系统；创建 Node 对象只是在 API 中增加代表节点的记录，不会自动创建机器或安装 kubelet。

常见流程是先准备机器和相关组件，再由配置正确的 kubelet 向 API Server 自动注册 Node 对象。也可以手动创建 Node 对象，但仍需要有对应的机器和 kubelet 才能实际运行工作负载。

文档：[Nodes — Management](https://kubernetes.io/docs/concepts/architecture/nodes/#management)、[Self-registration of Nodes](https://kubernetes.io/docs/concepts/architecture/nodes/#self-registration-of-nodes)。

## 2. 每个组件负责什么？

Q: API Server、etcd、scheduler、controller-manager、kubelet、容器运行时各自做什么？

A:

| 组件 | 职责 |
| --- | --- |
| API Server | 提供 Kubernetes API，处理请求及认证、授权、校验等，提供对象读写和 watch 接口。 |
| etcd | 持久化保存集群的 API 对象数据。 |
| scheduler | 为尚未分配节点的 Pod 选择合适的节点，并通过 API 提交绑定结果。 |
| controller-manager | 运行多个控制器，持续比较期望状态与观察状态，采取协调操作，例如创建或更新资源。 |
| kubelet | 管理本节点上的 Pod，通过容器运行时落实容器运行要求，并上报状态。 |
| 容器运行时 | 执行容器创建、启动、停止等操作。 |

这些组件不是逐级发命令的流水线。例如 ReplicaSet controller 通过 API Server 创建 Pod 对象，scheduler 为 Pod 选择节点，目标节点的 kubelet 观察到分配给自己的 Pod 后，再调用运行时。controller-manager 并不直接向 kubelet 下达启动命令。

文档：[Control Plane Components](https://kubernetes.io/docs/concepts/overview/components/#control-plane-components)、[Node Components](https://kubernetes.io/docs/concepts/overview/components/#node-components)、[Control via API server](https://kubernetes.io/docs/concepts/architecture/controller/#control-via-api-server)。

Q: 哪个组件决定 Pod 去哪个节点？

A: 通常由 scheduler 负责选择节点并提交绑定结果。

文档：[Control Plane Components — kube-scheduler 条目](https://kubernetes.io/docs/concepts/overview/components/#control-plane-components)。

Q: 哪个组件真正启动容器？

A: 容器运行时。kubelet 通过 CRI 调用运行时来落实容器启动等操作。

文档：[Node Components — kubelet 和 Container runtime 条目](https://kubernetes.io/docs/concepts/overview/components/#node-components)。

Q: 哪些信息存入 etcd，哪些只存在于节点或运行中的进程里？

A: 对于 Node、Pod、Deployment 等持久化的 API 对象，metadata、spec 和 status 都会通过 API Server 保存到 etcd。status 是对实际情况的记录，并不是运行中的进程本身。

| 信息 | 保存位置或方式 |
| --- | --- |
| Pod 的镜像配置、节点分配等 | 作为 API 对象的一部分保存到 etcd。 |
| 已上报的 Pod phase、容器状态、Pod IP 等 | 作为 status 的一部分保存到 etcd。 |
| 容器进程的内存、打开的连接等 | 位于节点或运行中的进程中，不作为这些 API 对象保存到 etcd。 |
| 容器日志正文、镜像文件、应用数据 | 通常位于节点文件系统、卷或专用存储系统中，不由 etcd 保存其正文。 |

因此，“status 只存在于节点或进程里”不正确。节点上的实际情况由组件观察后，将需要报告的信息写入 API 对象的 status。

文档：[The Kubernetes API — Persistence](https://kubernetes.io/docs/concepts/overview/kubernetes-api/#persistence)、[Object spec and status](https://kubernetes.io/docs/concepts/overview/working-with-objects/#object-spec-and-status)。

> 区分：接收请求、保存状态、做出决策、执行动作。

## 3. 组件怎样协作？

Q: 为什么组件通常通过 API Server 交换状态？

A: Kubernetes 的 API 通信采用 hub-and-spoke（中心—辐条）结构，API Server 是中心。它提供统一的资源访问入口，处理认证、授权、校验和并发更新，并通过 list/watch 提供对象数据和变化。

组件通过共享 API 对象协作，因此不需要彼此直接调用或分别直接访问 etcd。例如控制器创建 Pod 对象后，由 scheduler 和 kubelet 分别观察并处理。这种结构也使组件可以独立运行，并在重新连接后重新读取当前状态。

文档：[Node to Control Plane](https://kubernetes.io/docs/concepts/architecture/control-plane-node-communication/#node-to-control-plane)、[Kubernetes API Concepts](https://kubernetes.io/docs/reference/using-api/api-concepts/)、[Control via API server](https://kubernetes.io/docs/concepts/architecture/controller/#control-via-api-server)。

Q: list/watch 如何帮助组件发现变化？

A: list 获取某类资源的对象列表，通常包含 metadata、spec、status 等字段。watch 建立持续连接，接收资源新增、修改、删除等变化事件，而不是反复查询 resourceVersion 字段。

典型的 list/watch 流程：

1. list 获取对象列表，以及列表的 metadata.resourceVersion。
2. 使用该 resourceVersion 作为起点发起 watch，接收此后发生的变化。
3. 根据 ADDED、MODIFIED、DELETED 等事件更新本地缓存，并触发后续处理。
4. watch 中断后可以尝试从上次版本继续；如果历史版本已不可用（例如返回 410 Gone），通常需要重新 list 并建立 watch。

resourceVersion 是服务端提供的版本标识，用于变化追踪和并发控制。客户端应将它视为不透明的字符串，不自行按数字大小比较或递增。watch 还可能返回 BOOKMARK 等事件；上面列出的是主要对象变化事件。

文档：[Efficient detection of changes](https://kubernetes.io/docs/reference/using-api/api-concepts/#efficient-detection-of-changes)、[Resource versions](https://kubernetes.io/docs/reference/using-api/api-concepts/#resource-versions)。

- Controller 的控制循环是什么？一次操作失败后怎么办？
- 多个 Controller 如何通过不同资源串起一项工作？
例如，能解释这条链中每一步是谁完成的：
创建 Deployment
    → 创建 ReplicaSet
    → 创建 Pod
    → 为 Pod 选择节点
    → 启动容器
    → 更新运行状态
4. 节点如何加入集群、被判定为健康？
- kubelet 怎样知道 API Server 的地址，并获得身份凭据？
- 节点名如何确定，Node 对象由谁创建？
- Node .status 和 Lease 心跳分别解决什么问题？
- Ready=False 与 Ready=Unknown 有什么区别？
- 节点失联后，谁检测、谁处理 Pod，是否立即处理？
这些正是你前面的问题，可以逐渐串成一个完整过程。
5. 请求与数据分别经过哪里？
- kubectl get、logs、exec、attach、port-forward 的路径有什么不同？
- 哪些连接由 kubelet 发起，哪些由 API Server 发起？
- Pod 之间的业务流量是否经过 API Server？
- Service 如何把请求送到后端 Pod？
- DNS、CNI、Service 网络实现各负责哪一部分？
这里要分清：管理集群的 API 通信，与应用自身的业务通信。
6. 故障时会发生什么？
用具体场景检验理解：
- 容器进程退出了，谁重启它？
- Pod 被删除了，谁创建替代 Pod？
- 节点断电了，原来的 Pod 和替代 Pod 会怎样？
- API Server 暂时不可用，已经运行的容器是否还能运行？
- Controller 重启后，如何重新知道还有哪些工作没完成？
特别要分清：重启容器、创建新 Pod、增加新节点，是不同层次的恢复动作。
