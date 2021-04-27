

# kubernetes

二进制文件下载：[点击跳转](<https://github.com/kubernetes/kubernetes/releases>)

`Additional binary downloads are linked in the`

## INSTALL

参考地址：<https://developer.aliyun.com/mirror/kubernetes>

```shell
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
setenforce 0
yum install -y kubelet-1.17.5-0 kubeadm-1.17.5-0 kubectl-1.17.5-0
systemctl enable kubelet && systemctl start kubelet
```



## 扩展

### 容器健康检查

```yaml
        readinessProbe: # 如果未准备好 Controller会在Service中Endpoint删除该POD的IP地址
          httpGet:
            path: /healthcheck
            port: 8081
          initialDelaySeconds: 180 # 在容器启动多少秒之后执行探测
          timeoutSeconds: 15
        livenessProbe:  # 监测POD是否健康，判断容器是否重启
          httpGet:      # Http GET请求方法，400 < 返回码 >= 200;则成功
            path: /healthcheck  # 监测路径
            port: 8081          # 端口
          initialDelaySeconds: 180
          timeoutSeconds: 15    # 超时时间
          periodSeconds: 10     # 监测频率
```



### POD调度

#### nodeSelector 

定向调度

`Pod.spec.nodeName `：指定节点名称

```yaml
    spec:
      nodeName: k8s.node1 #指定调度节点为k8s.node1
      containers:
```

`Pod.spec.nodeSelector`：通过kubernetes的label-selector机制进行节点选择，进行label匹配，调度pod到目标节点

```shell
# 标记规则：kubectl label nodes <node-name> <label-key>=<label-value>
sudo kubectl label nodes k8s.node1 cloudnil.com/role=dev
    # 确认标记：kubectl get node  <node-name> --show-labels 
```

YAML

```yaml
    spec:
      nodeSelector:
        cloudnil.com/role: dev #指定调度节点为带有label标记为：cloudnil.com/role=dev的node节点
      containers:
```



#### 亲和度

`nodeAffinity` ： 主机亲和度；匹配目录：主机标签；将Pod部署到指定的符合标签规则的主机上。

`podAffinity`：POD亲和度；匹配目录：POD标签；

`podAntiAffinity`：POD反亲和度；匹配目录：POD标签；将一个服务的POD分散在不同的Node上。



`RequiredDuringSchedulingIgnoredDuringExecution`

要求满足亲和性或者反亲和性规则，如果不能满足规则，则POD不能被调度到对应的主机上。

`PreferredDuringSchedulingIgnoredDuringExecution`

尽量满足亲和性或者反亲和性规则，如果不能满足规则，POD也有可能被调度到对应的主机上。

列子

```yaml
  template:
    spec:     
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: beta.kubernetes.io/arch
                operator: In
                values:
                - amd64
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 1 # 权重，0~100的数值
            preference:  # 与权重相关的节点选择项
              matchExpressions: # 按节点标签列出的节点选择器要求列表
              - key: disk-type  # 键
                operator: In # 表示键与一组值的关系。有：In、NotIn、Exist、DoesNotExsit。GT和LT
                values:
                - ssd
# 只允许运行在amd64节点上，尽量运行在磁盘类型为ssd的节点上  
  
  
  template:
    spec:     
      affinity:
        nodeAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
            nodeSelectorTerms:
            - matchExpressions:
              - key: cs
                operator: In
                values:
                - nginx
# POD必须调度到包含cs=nginx的Node上

      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - nginx
# 不会调度到已经运行了label为app:nginx的Node上，Deployment副本就会部署到不同的Node上         

        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              topologyKey: kubernetes.io/hostname
              labelSelector:
                matchLabels:
                  app: nginx
# 尽量不调度到已经运行了label为app:nginx的Node                  
```



### 镜像拉取策略

`containers.name.imagePullPolicy`  

```shell
Always       # 不管本地是否存在总是拉取
IfNotPresent # 本地有则使用本地镜像,不拉取，默认值
Never        # 只使用本地镜像，从不拉取
```



### DaemonSet

在每一个节点上运行pod

```yaml
kind: DaemonSet
```

## Docker

参考地址：<https://kubernetes.io/docs/setup/production-environment/container-runtimes/>

```shell
# Install Docker CE
## Set up the repository
### Install required packages.
yum install -y yum-utils device-mapper-persistent-data lvm2

### Add Docker repository.
yum-config-manager --add-repo \
  https://download.docker.com/linux/centos/docker-ce.repo

## Install Docker CE.
yum update -y && yum install -y \
  containerd.io-1.2.13 \
  docker-ce-19.03.8 \
  docker-ce-cli-19.03.8

## Create /etc/docker directory.
mkdir /etc/docker

# Setup daemon.
cat > /etc/docker/daemon.json <<EOF
{
  "exec-opts": ["native.cgroupdriver=systemd"],
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m"
  },
  "storage-driver": "overlay2",
  "storage-opts": [
    "overlay2.override_kernel_check=true"
  ]
}
EOF

mkdir -p /etc/systemd/system/docker.service.d

# Restart Docker
systemctl daemon-reload
systemctl restart docker ; systemctl enable docker



# 镜像拉取

docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.4 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.4  ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.4 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.4   ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.4 k8s.gcr.io/kube-proxy:v1.17.4 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.4  k8s.gcr.io/kube-apiserver:v1.17.4 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.4 k8s.gcr.io/kube-controller-manager:v1.17.4  ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.4  k8s.gcr.io/kube-scheduler:v1.17.4 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 k8s.gcr.io/coredns:1.6.5  ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 k8s.gcr.io/etcd:3.4.3-0 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 k8s.gcr.io/pause:3.1 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.4 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.4  ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.4   ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.4   ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 

# v1.17.5

docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.5 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.5 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.5 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.5  ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 ;\
docker pull registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.5 k8s.gcr.io/kube-proxy:v1.17.5 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.5 k8s.gcr.io/kube-apiserver:v1.17.5 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.5 k8s.gcr.io/kube-controller-manager:v1.17.5 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.5 k8s.gcr.io/kube-scheduler:v1.17.5 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 k8s.gcr.io/coredns:1.6.5  ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 k8s.gcr.io/etcd:3.4.3-0 ;\
docker tag registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 k8s.gcr.io/pause:3.1 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-proxy:v1.17.5 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-apiserver:v1.17.5 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-controller-manager:v1.17.5  ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/kube-scheduler:v1.17.5  ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/coredns:1.6.5 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/etcd:3.4.3-0 ;\
docker rmi registry.cn-hangzhou.aliyuncs.com/opena/pause:3.1 
```

## HELM

[开源地址](<https://github.com/helm/helm/releases>)

```shell
tar -zxvf helm-v2.14.1-linux-amd64.tar.gz 

mv linux-amd64/helm /usr/bin/

helm init 
Creating /root/.helm 
Creating /root/.helm/repository 
Creating /root/.helm/repository/cache 
Creating /root/.helm/repository/local 
Creating /root/.helm/plugins 
Creating /root/.helm/starters 
Creating /root/.helm/cache/archive 
Creating /root/.helm/repository/repositories.yaml 
Adding stable repo with URL: https://kubernetes-charts.storage.googleapis.com 
Adding local repo with URL: http://127.0.0.1:8879/charts 
$HELM_HOME has been configured at /root/.helm.
Warning: Tiller is already installed in the cluster.
(Use --client-only to suppress this message, or --upgrade to upgrade Tiller to the current version.)

helm version
Client: &version.Version{SemVer:"v2.14.1", GitCommit:"5270352a09c7e8b6e8c9593002a73535276507c0", GitTreeState:"clean"}
Server: &version.Version{SemVer:"v2.14.1", GitCommit:"5270352a09c7e8b6e8c9593002a73535276507c0", GitTreeState:"clean"}
```

## EFK

日志收集

下载 源码文件 `kubernetes-server-linux-amd64.tar.gz`  解压

再解压`kubernetes-src.tar.gz`

进入到`cluster/addons/fluentd-elasticsearch/`目录

可选

1.master节点运行`fluentd-es-ds.yaml `

```yaml
    spec:
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      priorityClassName: system-node-critical
```

2.Ingress配置

```YAML
cat > ingress-kibana.yaml << EOF
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: ingress-kibana
  namespace: kube-system
  annotations:
    # use the shared ingress-nginx
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
  - host: kibana.uniaipcs.com
    http:
      paths:
      - path: /
        backend:
          serviceName: kibana-logging
          servicePort: 5601
EOF
```



```shell
$ kubectl apply -f .
```



## 监控

开源地址 <https://github.com/coreos/kube-prometheus>

快速安装：

```shell
git clone https://github.com/coreos/kube-prometheus.git
cd kube-prometheus/manifests
kubectl apply -f setup/.  
# 稍等会执行
kubectl apply -f .
```

创建`service`

```shell
cat > kube-controller-manager-service.yaml <<EOF
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: kube-controller-manager
  name: kube-controller-manager
  namespace: kube-system
spec:
  ports:
  - name: http-metrics
    port: 10252
    targetPort: 10252
  selector:
    component: kube-controller-manager
EOF

cat > kube-scheduler-service.yaml <<EOF
apiVersion: v1
kind: Service
metadata:
  labels:
    k8s-app: kube-scheduler
  name: kube-scheduler
  namespace: kube-system
spec:
  ports:
  - name: http-metrics
    port: 10251
    targetPort: 10251
  selector:
    component: kube-scheduler
EOF

kubectl apply -f kube-scheduler-service.yaml
kubectl apply -f kube-controller-manager-service.yaml
```



配置外部访问

```shell
cat > prometheus-Ingress.yaml <<EOF
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: prometheus.uniaipcs.com
  namespace: monitoring 
  annotations:
    # use the shared ingress-nginx
    kubernetes.io/ingress.class: "nginx"
    # nginx.ingress.kubernetes.io/ssl-redirect: 'true'
spec:
  rules:
  - host: prometheus.uniaipcs.com
    http:
      paths:
      - path: /
        backend:
          serviceName: prometheus-k8s
          servicePort: 9090
  - host: alert.uniaipcs.com
    http:
      paths:
      - path: /
        backend:
          serviceName: alertmanager-main
          servicePort: 9093
  - host: grafana.uniaipcs.com
    http:
      paths:
      - path: /
        backend:
          serviceName: grafana
          servicePort: 3000
EOF
```



报警通知配置`alertmanager-secret.yaml`

```yaml
apiVersion: v1
data: {}
kind: Secret
metadata:
  name: alertmanager-main
  namespace: monitoring
stringData:
  alertmanager.yaml: |-
    "global":
      "smtp_from": "auto_deploy@dadingsoft.com"
      "smtp_smarthost": "smtp.exmail.qq.com:25"
      "smtp_auth_username": "auto_deploy@dadingsoft.com"
      "smtp_auth_password": "1ut0_deploy@Dad1ngs0ft.com"
      "resolve_timeout": "5m"
    "inhibit_rules":
    - "equal":
      - "namespace"
      - "alertname"
      "source_match":
        "severity": "critical"
      "target_match_re":
        "severity": "warning|info"
    - "equal":
      - "namespace"
      - "alertname"
      "source_match":
        "severity": "warning"
      "target_match_re":
        "severity": "info"
    "receivers":
    - "name": "wechat"
      "email_configs":
      - "to": "fanchengdong@dadingsoft.com"
        "send_resolved": true
      "wechat_configs":
      - "corp_id": "wwd5e8d790a5b66fb7"
        "agent_id": "1000003"
        "api_secret": "YWF4TXXs3dQvE-906ovKwL3eAY_l286LJZjnWskeZcE"
        "send_resolved": false
        "to_party": "2"
    "route":
      "group_by":
      - "job"
      "group_interval": "5m"
      "group_wait": "30s"
      "receiver": "wechat"
      "repeat_interval": "12h"
type: Opaque
```



```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx-deployment
  labels:
    app: nginx
spec:
  replicas: 3
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - name: nginx
        image: nginx:1.14.2
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: nginx
  name: nginx
spec:
  type: ClusterIP
  selector:
    app: nginx
  ports:
    - name: port
      protocol: TCP
      port: 80
---

apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: nginx-web
  namespace: monitoring
  labels:
    app: nginx
spec:
  jobLabel: app
  endpoints:
  - port: port
    interval: 30s
    path: /
  selector:
    matchLabels:
      app: nginx
  namespaceSelector:
    matchNames:
    - default
```

修改存储持久化，保留时长

`prometheus-prometheus.yaml `

```yaml
spec:
  retention: 30d   # 数据保留30天
  alerting:
    alertmanagers:
# --------- 数据持久化 --------  参考NFS动态存储  
  storage:
    volumeClaimTemplate:
      spec:
        storageClassName: managed-nfs-storage
        accessModes: ["ReadWriteOnce"]
        resources:
          requests:
            storage: 100Gi       
```



## ingress

项目地址：<https://kubernetes.github.io/ingress-nginx/>

部署：

```shell
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.30.0/deploy/static/mandatory.yaml
namespace/ingress-nginx created
configmap/nginx-configuration created
configmap/tcp-services created
configmap/udp-services created
serviceaccount/nginx-ingress-serviceaccount created
clusterrole.rbac.authorization.k8s.io/nginx-ingress-clusterrole created
role.rbac.authorization.k8s.io/nginx-ingress-role created
rolebinding.rbac.authorization.k8s.io/nginx-ingress-role-nisa-binding created
clusterrolebinding.rbac.authorization.k8s.io/nginx-ingress-clusterrole-nisa-binding created
deployment.apps/nginx-ingress-controller created
limitrange/ingress-nginx created

# 可以修改DeployMent -> DaemonSet， 添加参数
      hostNetwork: true
```

创建 Ing

```yaml
cat > cc.yaml <<EOF
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  name: ingress-kibana
  namespace: kube-system
  annotations:
    # use the shared ingress-nginx
    kubernetes.io/ingress.class: "nginx"
spec:
  rules:
  - host: kibana.dadingsoft.com
    http:
      paths:
      - path: /
        backend:
          serviceName: kibana-logging
          servicePort: 5601
EOF
```

创建`ingress-nginx` - Service ,  可不创建

```yaml
cat > ingress-nginx-service.yaml <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ingress-nginx
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
spec:
  type: NodePort
  ports:
    - name: http
      port: 80
      targetPort: 80
      protocol: TCP
      nodePort: 32080  #http
    - name: https
      port: 443
      targetPort: 443
      protocol: TCP
      nodePort: 32443  #https
  selector:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
EOF
```



微信认证MP文件

```yaml
metadata:
  name: ingress-kibana
  namespace: kube-system
  annotations:
    # use the shared ingress-nginx
    kubernetes.io/ingress.class: "nginx"
    nginx.ingress.kubernetes.io/server-snippet: |
        location /MP_verify_dwlmVn4w5TXj2A497D.txt {
          alias  /etc/nginx/MP_verify_dwlmVn4w5TXj2A497D.txt;
        }
```

进入到容器添加文件

```shell
kubectl exec -it ingress-nginx-controller-9cbcc968f-5n4gp bash -n ingress-nginx
echo 'dwlmVn4w5TXj2A497D' > MP_verify_dwlmVn4w5TXj2A497D.txt
```



## statefulset

有状态服务

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  labels:
    app: nginx
spec:
  ports:
  - port: 80
    name: web
  clusterIP: None
  selector:
    app: nginx
---
apiVersion: apps/v1
kind: StatefulSet
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: nginx # has to match .spec.template.metadata.labels
  serviceName: "nginx"
  replicas: 3 # by default is 1
  template:
    metadata:
      labels:
        app: nginx # has to match .spec.selector.matchLabels
    spec:
      terminationGracePeriodSeconds: 10
      containers:
      - name: nginx
        image: k8s.gcr.io/nginx-slim:0.8
        ports:
        - containerPort: 80
          name: web
        volumeMounts:
        - name: www
          mountPath: /usr/share/nginx/html
  volumeClaimTemplates:
  - metadata:
      name: www
    spec:
      accessModes: [ "ReadWriteOnce" ]
      storageClassName: "my-storage-class"
      resources:
        requests:
          storage: 1Gi
```

- 名为 `nginx` 的 Headless Service 用来控制网络域名。
- 名为 `web` 的 StatefulSet 有一个 Spec，它表明将在独立的 3 个 Pod 副本中启动 nginx 容器。
- `volumeClaimTemplates` 将通过 PersistentVolumes 驱动提供的 [PersistentVolumes](https://kubernetes.io/zh/docs/concepts/storage/persistent-volumes/) 来提供稳定的存储。

## Cert-Manage

开源地址：<https://cert-manager.io/docs/installation/kubernetes/>

```shell
kubectl create namespace cert-manager
kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.10.0/cert-manager.yaml

kubectl get pod -n cert-manager 
NAME                                       READY   STATUS              RESTARTS   AGE
cert-manager-57c65cb5f5-cf7sg              0/1     Running             0          14s
cert-manager-cainjector-6f868ccdf6-qv6mf   1/1     Running             0          14s
cert-manager-webhook-5896b5fb5c-vkbgt      0/1     Running             0          14s

git clone https://github.com/kevinniu666/cert-manager-webhook-alidns.git
cd cert-manager-webhook-alidns/
helm install --name cert-manager-webhook-alidns --namespace=cert-manager ./deploy/webhook-alidns

kubectl get pod -n cert-manager
NAME                                          READY   STATUS    RESTARTS   AGE
cert-manager-57c65cb5f5-cf7sg                 1/1     Running   0          16m
cert-manager-cainjector-6f868ccdf6-qv6mf      1/1     Running   0          16m
cert-manager-webhook-5896b5fb5c-vkbgt         1/1     Running   0          16m
cert-manager-webhook-alidns-d5b8d5f9d-44kgv   1/1     Running   0          16m


kubectl -n cert-manager create secret generic alidns-uniaipcq --from-literal=accessKeySecret='MpLrvtt0x1ylME*****V0sZNWPQsqL'
```

**添加权限**

默认`resourceNames` 中只包含 `secret/alidns-credentials` 

```shell
kubectl edit clusterrole cert-manager-webhook-alidns:secret-reader
....
  resourceNames:
  - alidns-credentials
  - alidns-uniaipcq
....  
```

创建`clusterissuer`文件

```shell
apiVersion: certmanager.k8s.io/v1alpha1
kind: ClusterIssuer
metadata:
  name: letsencrypt-uniaipcq
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: fanchengdong@dadingsoft.com
    privateKeySecretRef:
      name: letsencrypt-uniaipcq
    solvers:
    - selector: 
        dnsNames:
        - '*.app.uniaipcq.com'   # 证书域名地址
      dns01:
        webhook:
          config:
            accessKeyId: LTAI*******Ueyy  # 阿里云accessKeyId
            accessKeySecretRef:
              key: accessKeySecret
              name: alidns-uniaipcq  # 与secret对应
            regionId: "cn-shenzhen"
            ttl: 600
          groupName: certmanager.webhook.alidns
          solverName: alidns
```

```shell
kubectl apply -f clusterissuer.yaml
kubectl get clusterissuer
NAME               AGE
letsencrypt-uniaipcq   7s
```

创建 `ingress` 

```shell
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: cps.app.uniaipcq.com
  namespace: default
  annotations:
    certmanager.k8s.io/cluster-issuer: "letsencrypt-uniaipcq"  # 与ClusterIssuer对应
    nginx.ingress.kubernetes.io/ssl-redirect: 'true'  # 强制跳转https
spec:
  tls:
  - hosts:
    - 'cps.app.uniaipcq.com'
    secretName: uniaipcq-com-tls
  rules:
  - host: cps.app.uniaipcq.com
    http:
      paths:
      - path: /
        backend:
          serviceName: nginx
          servicePort: 80
```

```shell
kubectl apply -f ingress.yaml  # 创建之后，cert-manager会自动根据域名去创建certificate, order, challenge等

kubectl get ing
NAME                   HOSTS                  ADDRESS           PORTS     AGE
cps.app.uniaipcq.com   cps.app.uniaipcq.com   121.1**.195.226   80, 443   159m

kubectl get certificate
NAME               READY   SECRET             AGE
uniaipcq-com-tls   True    uniaipcq-com-tls   157m
# REDAY是True就代表证书从letsencrypt下发成功了


# 查看状态，challenge在成功验证后会被自动删除
kubectl get challenge
```

## rollingUpdate

> 更新策略

```yaml
spec:
  strategy:
    rollingUpdate:
      maxSurge: 1   # 启动创建的副本数
      maxUnavailable: 50%  # 停止多少个
    type: RollingUpdate
```



## ConfigMap

创建ConfigMap的方式有4种：

- 通过直接在命令行中指定configmap参数创建，即`--from-literal`
- 通过指定文件创建，即将一个配置文件创建为一个ConfigMap，`--from-file=<文件>`
- 通过指定目录创建，即将一个目录下的所有配置文件创建为一个ConfigMap，`--from-file=<目录>`
- 写好标准的configmap的yaml文件，然后`kubectl create -f` 创建

### from-literal

```shell
# 创建 configmap
kubectl create configmap dbconfig \
--from-literal=db.host=172.18.56.43  \
--from-literal=db.user=root  \
--from-literal=db.passwd=password
# 查询 configmap
kubectl get configmap dbconfig -o yaml
apiVersion: v1
data:
  db.host: 172.18.56.43
  db.passwd: password
  db.user: root
kind: ConfigMap
metadata:
  creationTimestamp: 2019-12-05T06:04:07Z
  name: dbconfig
  namespace: default
  resourceVersion: "72017917"
  selfLink: /api/v1/namespaces/default/configmaps/dbconfig
  uid: 0c38d885-1725-11ea-b134-000c2925465f
```

#### 环境变量

```yaml
spec:
  template:
    spec:  
      containers:
      - name: alertcenter
        envFrom:      
        - configMapRef:
            name: dbconfig   # configmap 名称
```

进入容器查看

```shell
env | grep db
db.host=172.18.56.47
db.passwd=ad1211
db.user=root
```

#### 文件挂载

```yaml
spec:
  template:
    spec:  
      containers:
      - name: alertcenter
        volumeMounts:
        - name: config-volume
          mountPath: /etc/config
      volumes:
        - name: config-volume
          configMap:
            name: dbconfig    # configmap 名称
```

进入容器查看

```shell
ls /etc/config/ -l
total 0
lrwxrwxrwx 1 root root 14 Dec  5 06:58 db.host -> ..data/db.host
lrwxrwxrwx 1 root root 16 Dec  5 06:58 db.passwd -> ..data/db.passwd
lrwxrwxrwx 1 root root 14 Dec  5 06:58 db.user -> ..data/db.user
```



### from-file

```shell
# 创建配置文件
cat db.conf
db.host=172.18.56.43
db.passwd=password
db.user=root
# 创建configmap
kubectl create configmap dbconfig02 --from-file=./db.conf
# 查询configmap
kubectl get configmap dbconfig02 -o yaml
apiVersion: v1
data:
  db.conf: |
    db.host=172.18.56.43
    db.passwd=password
    db.user=root
kind: ConfigMap
metadata:
  creationTimestamp: 2019-12-05T06:12:39Z
  name: dbconfig02
  namespace: default
  resourceVersion: "72018849"
  selfLink: /api/v1/namespaces/default/configmaps/dbconfig02
  uid: 3d30285f-1726-11ea-b134-000c2925465f
```

#### 文件挂载

```yaml
spec:
  template:
    spec:  
      containers:
      - name: alertcenter
        volumeMounts:
        - name: config-volume
          mountPath: /etc/config
      volumes:
        - name: config-volume
          configMap:
            name: dbconfig02    # configmap 名称
```

进入容器查看

```shell
cat /etc/config/db.conf 
db.host=172.18.56.43
db.passwd=password
db.user=root
```



## python client

token创建

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: admin-user
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: admin-user
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: admin-user
  namespace: kube-system
```

查看token

```shell
kubectl describe secret $(kubectl get secret -n kube-system | grep ^admin-user | awk '{print $1}') -n kube-system | grep -E '^token'| awk '{print $2}'
```



```python
# -*- coding: utf-8 -*-

from kubernetes import client, config
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Kubernetes:
    def __init__(self):
        config.kube_config.load_kube_config(config_file="F:\\config.yaml")
        
        # 第二种认证方式，参考token创建
        # token = ''
        # configuration = client.Configuration()
        # configuration.host = "https://192.168.1.214:8443"
        # configuration.verify_ssl = False
        # configuration.api_key['authorization'] = token
        # configuration.api_key_prefix['authorization'] = 'Bearer'
        # client.Configuration.set_default(configuration)
        
        
        self.Connect = client.CoreV1Api()
        self.api_instance = client.AppsV1Api()

    def list_namespaces(self):
        """
        查询所有namespaces名称
        :return:
        """

        data = []
        for ns in self.Connect.list_namespace().items:
            data.append(ns.metadata.name)
        return data

    def create_namespaces(self, name):
        """
        创建 namespaces
        :param name: namespaces名称
        :return:
        """

        body = client.V1Namespace()
        body.metadata = client.V1ObjectMeta(name=name)
        return self.Connect.create_namespace(body=body)

    def update_image(self, namespace, deployment, image):
        """
        更新镜像
        :param namespace: namespaces名称
        :param deployment: deployment名称
        :param image: 镜像
        :return:
        """

        body = self.api_instance.read_namespaced_deployment(deployment, namespace)
        print(body)
        body.spec.template.spec.containers[0].image = image
        self.api_instance.replace_namespaced_deployment(deployment, namespace, body)

    def deployment_status(self, namespace, deployment):
        """
        查询deployment状态,可比对容器数，image标签判断是否发布完成
        :param namespace:
        :param deployment:
        :return:
        """
        api_response = self.api_instance.read_namespaced_deployment_status(deployment, namespace)
        print(api_response)

    def replace_config_map(self, namespace, name):
        """
        更新 config map
        :param namespace: 空间名称
        :param name: config map 名称
        :return:
        """
        body = self.Connect.read_namespaced_config_map(name, namespace)
        print(body)
        # body.data = {'app.config': 'n=1\na=2\nc=3\np=9\nIPADDR=192.168.1.1'}
        body.data = {'db.host': '172.18.56.47', 'db.passwd': 'ad1211', 'db.user': 'root'}
        print(self.Connect.replace_namespaced_config_map(name, namespace, body))

    def create_config_map(self, namespace, config_name, config_data):
        body = client.V1ConfigMap()
        data = ''
        for key in config_data.keys():
            data += str(key) + '=' + str(config_data[key]) + '\n'
        body.data = {config_name: data}
        body.metadata = {'name': 'game-config-3'}
        self.Connect.create_namespaced_config_map(namespace, body)


k = Kubernetes()
# print(k.list_namespaces())

# print(k.create_namespaces("fan"))

# k.update_image('default', 'alertcenter', 'nginx:1.19')

# k.deployment_status("ceshi", "ceshi-agent")

k.replace_config_map("default", "dbconfig")


# config_data = {'hostname': 'node01', 'ip': '120.78.14.105'}
# config_name = 'weixin.conf'
# namespaces = 'default'
#
# k.create_config_map(namespaces, config_name, config_data)
```

配置文件`config.yaml`中需要添加：

```shell
clusters:
- cluster:
    insecure-skip-tls-verify: true  # 添加内容
```





## blackbox

> 站点监控

`prometheus-blackbox-exporter-deployment.yaml`

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: prometheus-blackbox-exporter
  labels:
    app: prometheus-blackbox-exporter
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus-blackbox-exporter
  template:
    metadata:
      labels:
        app: prometheus-blackbox-exporter
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: prometheus-blackbox-exporter
              topologyKey: kubernetes.io/hostname
            weight: 100
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - prometheus-blackbox-exporter
            topologyKey: kubernetes.io/hostname
      containers:
      - name: prometheus-blackbox-exporter
        image: registry.cn-hangzhou.aliyuncs.com/opena/blackbox-exporter:v0.18.0
        ports:
        - containerPort: 9115
        livenessProbe:
          failureThreshold: 3
          initialDelaySeconds: 60
          periodSeconds: 10
          successThreshold: 1
          tcpSocket:
            port: 9115
          timeoutSeconds: 15
        name: container-0
        readinessProbe:
          failureThreshold: 3
          initialDelaySeconds: 60
          periodSeconds: 10
          successThreshold: 1
          tcpSocket:
            port: 9115
          timeoutSeconds: 15
        resources:
          limits:
            cpu: 300m
            memory: 512M
          requests:
            cpu: 300m
            memory: 512M
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: prometheus-blackbox-exporter
  name: prometheus-blackbox-exporter
  namespace: monitoring
spec:
  type: ClusterIP
  selector:
    app: prometheus-blackbox-exporter
  ports:
    - name: port
      protocol: TCP
      port: 9115
```

配置

`prometheus-blackbox-exporter.yaml `

```yaml
  - job_name: 'blackbox'
    metrics_path: /probe
    params:
      module: [http_2xx]  # Look for a HTTP 200 response.
    file_sd_configs:       # 动态加载文件,前提prometheus挂载了数据存储
     - files:
         - /prometheus/blackbox/*.yaml
    #static_configs:
    #  - targets:
    #    - http://zabbix.ops.360humi.com    # Target to probe with http.
    #    - https://www.360humi.com   # Target to probe with https.
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: prometheus-blackbox-exporter.monitoring.svc.cluster.local:9115  # The blackbox exporter's real hostname:port.
```

> 在数据库存储创建blackbox目录， 创建 `monitor_urls.yaml`文件
>
> ```
> - targets:
>    - https://www.360humi.com
>    - http://jenkins.ops.360humi.com/login?from=%2F
>    - https://hiip.360humi.com/login
>    - https://hikg.360humi.com
>    - https://hiip.360humi.com
>    - http://hias.360humi.com
>    - https://hiip.360humi.com/login
>    - https://h-5gec.360humi.com
>    - https://bus.360humi.com
>    - https://apis.360humi.com/login
> ```
>
> 


```shell
kubectl create secret generic prometheus-blackbox-exporter --from-file=prometheus-blackbox-exporter.yaml -n monitoring 
```

`prometheus-prometheus.yaml ` 添加

```yaml
  additionalScrapeConfigs:
    name: prometheus-blackbox-exporter
    key: prometheus-blackbox-exporter.yaml
  externalUrl: http://prometheus.k8s.360humi.com/  # 如果前面有代理需要配置这玩意,不然监控图标点不开。    
```

`prometheus-rules.yaml ` 添加

```yaml
  - name: WebMonitoring
    rules:
    - alert: 'blackbox 检测异常'
      annotations:
        description: Website - {{ $labels.instance }} is down
        summary:  WebSite is down
      expr: |
        probe_success == 0
      for: 3m
      labels:
        severity: critical
    - alert: 'blackbox web检查失败'
      annotations:
        description: " WEB {{ $labels.instance }} 访问失败，请核实"
        summary:  WebSite is down
      expr: |
        probe_http_status_code != 200
      for: 3m
      labels:
        severity: critical
```

```shell
kubectl apply -f prometheus-rules.yaml
```



## webhook-dingtalk

> 钉钉通知

`prometheus-webhook-dingtalk.yaml `

```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: prometheus-webhook-dingtalk
  labels:
    app: prometheus-webhook-dingtalk
  namespace: monitoring
spec:
  replicas: 1
  selector:
    matchLabels:
      app: prometheus-webhook-dingtalk
  template:
    metadata:
      labels:
        app: prometheus-webhook-dingtalk
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - podAffinityTerm:
              labelSelector:
                matchLabels:
                  app: prometheus-webhook-dingtalk
              topologyKey: kubernetes.io/hostname
            weight: 100
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - prometheus-webhook-dingtalk
            topologyKey: kubernetes.io/hostname
      containers:
      - name: prometheus-webhook-dingtalk
        image: registry.cn-hangzhou.aliyuncs.com/opena/prometheus-webhook-dingtalk:v1.4.6
        env:
        - name: ACCESS_TOKEN
          value: 983f455987ecdc89071d4108ad257da5f777cd570442e99e3442e478e98aa53a
        ports:
        - containerPort: 8060
        livenessProbe:
          failureThreshold: 3
          initialDelaySeconds: 60
          periodSeconds: 10
          successThreshold: 1
          tcpSocket:
            port: 8060
          timeoutSeconds: 15
        name: container-0
        readinessProbe:
          failureThreshold: 3
          initialDelaySeconds: 60
          periodSeconds: 10
          successThreshold: 1
          tcpSocket:
            port: 8060
          timeoutSeconds: 15
        resources:
          limits:
            cpu: 200m
            memory: 256M
          requests:
            cpu: 100m
            memory: 256M          
---
apiVersion: v1
kind: Service
metadata:
  labels:
    app: prometheus-webhook-dingtalk
  name: prometheus-webhook-dingtalk
  namespace: monitoring
spec:
  type: ClusterIP
  selector:
    app: prometheus-webhook-dingtalk
  ports:
    - name: port
      protocol: TCP
      port: 8060
```

配置

`alertmanager.yaml`

```yaml
# external alertmanager yaml
global:
  resolve_timeout: 10m
route:
  group_by: ['job']
  group_wait: 31s
  group_interval: 5m
  repeat_interval: 12h
  receiver: 'dingding'
receivers:
- name: "dingding"
  webhook_configs:
  - url: 'http://prometheus-webhook-dingtalk.monitoring.svc.cluster.local:8060/dingtalk/webhook2/send'
```

```shell
kubectl delete secret alertmanager-main -n monitoring
kubectl create secret generic alertmanager-main --from-file=alertmanager yaml -n monitoring 
```



## NFS动态存储

>  [github地址](https://github.com/kubernetes-sigs/nfs-subdir-external-provisioner)

```shell
cd nfs-subdir-external-provisioner-master/deploy
# Set the subject of the RBAC objects to the current namespace where the provisioner is being deployed
$ NS=$(kubectl config get-contexts|grep -e "^\*" |awk '{print $5}')
$ NAMESPACE=${NS:-default}
$ sed -i'' "s/namespace:.*/namespace: $NAMESPACE/g" ./deploy/rbac.yaml ./deploy/deployment.yaml
$ kubectl create -f rbac.yaml

```



## node_exporter指标

```yaml
node_arp_entries: 节点上arp条目数, shell: arp -a
node_boot_time_seconds: 系统启动时间(时间戳格式), shell: who -b  或者 cat /proc/stat  | grep btime
node_context_switches_total: 上下文切换累计总数, shell: cat /proc/stat|grep ctxt
node_cpu_seconds_total: cpu统计信息

```

