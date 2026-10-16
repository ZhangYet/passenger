# kubernetes Q&A

## 1. 用户提交的到底是什么？
Q: YAML 如何对应 API 对象？

A: YAML 包括了 API 对象的 Spec 和 Status， 见 [objects](https://kubernetes.io/docs/concepts/overview/working-with-objects/)

Q: apiVersion、kind、metadata、spec、status 分别表示什么？
A:

1. apiVersion - Which version of the Kubernetes API you're using to create this object
2. kind - What kind of object you want to create
3. metadata - Data that helps uniquely identify the object, including a name string, UID, and optional namespace
4. spec - What state you desire for the object
5. status - current state of this object

Q: 期望状态和实际状态有什么区别，分别由谁更新？

A: 期望状态由 Spec 决定，实际状态是 object 实际的状态，前者由用户更新，后者由 k8s 系统决定。

Q: 创建一个 Node 对象，与创建一台机器有什么区别？
A: 没懂

## 2. 每个组件负责什么？
Q: API Server、etcd、scheduler、controller-manager、kubelet、容器运行时各自做什么？
A:

API Server: 接收请求。
Scheduler: 决策。
Controller-manager: 发出执行。
kubelet: 实际执行。
容器运行时：运行容器。

Q: 哪个组件决定 Pod 去哪个节点？

A: scheduler

Q: 哪个组件真正启动容器？

A: 容器运行时。

Q: 哪些信息存入 etcd，哪些只存在于节点或运行中的进程里？

A: Object Spec 会被存入 etcd, Status 只存在于节点或进程里面

> 你应该能清楚地区分：接收请求、保存状态、做出决策、执行动作。

## 3. 组件怎样协作？
Q: 为什么组件通常通过 API Server 交换状态？

A: Kubernetes has a "hub-and-spoke" API pattern

Q: list/watch 如何帮助组件发现变化？

A: 我认为应该是[这篇文档](https://kubernetes.io/docs/reference/using-api/api-concepts/) 里面提到的，我的理解是 list 可以列出 object 的状态，watch 会持续观察 resourceVersion 字段。

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
