# RustFS 发布门禁

`make release-gate` 是单个 RustFS 发布标签的入口。它记录版本、上一版本、
镜像、git SHA 和制品校验和，然后按层级跑用例，并写出：

- `target/release-gate/<version>/<tier>/<run-id>/release-gate.json`
- `target/release-gate/<version>/<tier>/<run-id>/release-gate.junit.xml`
- `target/release-gate/<version>/<tier>/<run-id>/RELEASE_GATE.md`

用 `RELEASE_GATE_OUTPUT` 指定目录。用 `RELEASE_GATE_RUN_ID` 固定默认目录。
实跑会先删掉该目录里由脚本产生的证据，除非 `RELEASE_GATE_REUSE_EVIDENCE=1`。

每条用例是 `PASS`、`FAIL` 或 `SKIP`。跳过原因以稳定代码开头。缺证据和
配置错误都让门禁失败。下面这些跳过不会让门禁失败：

| 代码 | 允许的条件 |
| --- | --- |
| `SKIP-dry-run` | `RELEASE_GATE_DRY_RUN=1` |
| `SKIP-toda-arm64` | IOChaos 或 warp-under-chaos，且该架构的 chaos-daemon toda 二进制无法运行（Apple Silicon） |
| `SKIP-no-dm` | 未设置 `RUSTFS_RELEASE_GATE_HAS_DM` 时的 device-mapper 场景 |
| `SKIP-timechaos` | `clock-skew`；TimeChaos 仍是目录中的 Planned |
| `SKIP-planned` | 目录中仍为 Planned 的管理面和存储资格场景，包括 expand、rebalance、decommission，直到它们可执行 |
| `SKIP-dm-not-selected` | 除 `RELEASE_GATE_DM_SCENARIO`（默认 `dm-flakey`）以外的 device-mapper 场景。一次门禁只跑一个 DM 场景 |
| `DEFERRED-physical-power` | 物理断电；`pod-kill-one` 和 `pod-graceful-restart-one` 是替代项 |
| `SKIP-no-prev-version` | 没有 `RUSTFS_PREV_VERSION` 时的升级、回滚或 warp 回归 |
| `SKIP-no-artifact` | 仅限 `RELEASE_GATE_FETCH=0` 的 dry-run |
| `SKIP-no-cluster` | 仅限 dry-run；实跑把这项当成门禁失败 |

这些状态不算通过：`SKIP-no-mc`、`SKIP-no-privileged`、
`SKIP-unsafe-shared-fs`、`SKIP-no-dm-device`、`SKIP-dm-in-use`、
`SKIP-dm-topology`、`SKIP-no-unzip`、`SKIP-no-otool`、`SKIP-aborted`，
以及任何其他代码。
开启 fetch 的实跑在
缺少校验和、`--version` 或 `ldd`/`otool` 输入时失败。
`volume-remount-ro` 先检查能力，再检查是否共享文件系统。operator Pod
丢掉全部 capability 时（包括 local-path）记为 `SKIP-no-privileged`，
这不是覆盖。`disk-full-fill` 仍然先拒绝共享文件系统
（`SKIP-unsafe-shared-fs`）。

## 命令

```bash
# 规划全部用例并核对已发布制品。不接触集群。
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_PREV_VERSION=1.0.0 \
  RELEASE_GATE_TIER=full \
  RELEASE_GATE_DRY_RUN=1

# 在准备好的集群上做实跑 smoke。镜像默认取 RUSTFS_IMAGE。
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_IMAGE=rustfs/rustfs:1.0.1-preview.11 \
  RELEASE_GATE_TIER=smoke \
  RELEASE_GATE_DRY_RUN=0 \
  RUSTFS_RELEASE_GATE_HAS_CLUSTER=1

# standard：smoke，再加上网络、重启、quorum-edge、协议回归、
# lifecycle、warp 回归和升级。
make release-gate RUSTFS_VERSION=1.0.1-preview.11 RUSTFS_PREV_VERSION=1.0.0 RELEASE_GATE_TIER=standard
```

`RELEASE_GATE_FETCH=1`（Make 的默认值）先下载 `SHA256SUMS`，再下载
`rustfs/rustfs` 上该主机架构的每个 zip。每次下载最多重试三次，GitHub
给出大小时必须与资产大小一致，并且必须与 SHA256SUMS 摘要一致。不一致就
删掉文件再重试。fetch 失败或镜像构建失败时，实跑在任何用例接触集群之前
中止：其余集群用例记为 `SKIP-aborted`，结论为失败。设置
`RELEASE_GATE_FETCH=0` 则只给 `RUSTFS_ARTIFACT_DIR` 里已有的文件打分。

主机 zip 集合是该架构的每一个 Linux zip，不是目录里的第一个条目。每个
zip 单独记录 `ldd`（gnu 写入 `rustfs-ldd.txt`，musl 写入
`rustfs-ldd-musl.txt`）。静态 musl 二进制不会掩盖 gnu 二进制里的非系统库。
存在 gnu zip 时，容器镜像用它来构建；`rustfs-image-libc.txt` 记录 `gnu`
或 `musl`。在 Linux 上，`--version` 取自该二进制，非零退出会被记录，
不会当成成功。在 macOS 上，`--version` 和 `otool -L` 都取自 macOS zip
（`rustfs-version.txt`、`rustfs-otool.txt`）。dyld 无法加载时仍然采集
`otool -L`。Homebrew 装在 `/opt/homebrew` 下的 `liblzma` 会使
dynamic-deps 失败。git SHA 来自 `git commit` 行；当
`target_commitish` 是分支名时，来自 tag 对象。

实跑集群上若未设置 `RUSTFS_IMAGE` 或 `RUSTFS_PREV_IMAGE`，门禁用 gnu
二进制构建 `rustfs-release:<tag>`（`scripts/release-gate-image.sh`）。
默认基础镜像是 `debian:bookworm-slim`。证书包为空时 Dockerfile 安装
`ca-certificates`，然后在使用镜像之前冒烟检查 `--version` 和非空的
`/etc/ssl/certs/ca-certificates.crt`。`RUSTFS_RELEASE_GATE_BINARY_PATH`
默认为 `/usr/bin/rustfs`。

docker、nerdctl 和 buildah 使用 `--network=host` 构建，因此安装
`ca-certificates` 不依赖容器 bridge。虚拟机访问不了 Docker Hub 时，先把
基础镜像载入：在能拉取的机器上执行
`docker pull --platform linux/arm64 debian:bookworm-slim`（平台换成虚拟机
的架构），再在虚拟机上执行
`docker save debian:bookworm-slim | docker load`。门禁仍使用默认基础镜像
名。安装了 `k3s` 时，镜像导入
containerd 命名空间 `k8s.io`，并按 `docker.io/library/<name>:<tag>` 打上
`io.cri-containerd.pinned=pinned`。pin 失败不会被忽略。`k3s ctr` 需要
containerd 套接字。套接字仅 root 可写时，脚本使用 `sudo -n`，失败时给出
该提示，不会交互询问密码。kubelet 看不到的构建是失败。缺少构建器或
二进制也是失败。

`fresh-install` 在协议 smoke、大对象 GET 和 lifecycle 之前部署
`RUSTFS_IMAGE`（与升级相同的 Tenant 注解和 Pod 等待）。部署失败后，
后续集群用例记为 `SKIP-aborted`，避免它们跑在上一版镜像上。

协议套件在每条用例开始时规划目标指纹，并设置
`RUSTFS_PROTOCOL_TEST_DEDICATED=1` 和该计划的
`RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT`。同时设置协议框架已经要求的
`RUSTFS_PROTOCOL_TEST_ENDPOINT` 和管理员凭据变量。每次门禁都会重新计算
指纹，包括 `cluster-cold-restart` 替换 Tenant 之后。

层级：

- **smoke** — 制品身份、协议 smoke、大对象 GET、全新安装、
  `pod-kill-one`、`pod-graceful-restart-one`、故障后校验和。
- **standard** — smoke，加上网络故障、重启风暴、滚动重启和冷重启、
  quorum edge、冷桶存活探针、toda 可用时的 IOChaos、不用 IOChaos 的
  磁盘填满和只读重挂载、协议回归、lifecycle、warp 回归、升级和回滚。
- **full** — standard，加上 device-mapper、warp-under-chaos、其余
  IOChaos、计划中的管理面/存储资格、expand，以及推迟的物理断电行。

## 证据文件

把这些 JSON 放进制品目录，就可以不重跑该用例而直接打分。这是 Mac Mini
战役已经产出的契约。

- `quorum-edge-cold-read.json` — `survivors[]`。`cold_bucket` 是布尔值，
  为真表示该存活者从未服务过这个桶（不是桶名）。每个存活者有 `name`、
  `get_ok`、`get_attempted`、`wrong_sha256`、`put_rejected`、
  `put_attempted`、`health_live` 和 `health_ready`。
  `quorum-edge-cold-read` 要求至少两个存活者、其中一个是冷的、每次 GET
  成功、每次 PUT 被拒绝，且 `health_live` 为 200。它不看就绪。
  `quorum-edge-readiness` 要求每个存活者的 `health_ready` 为 200。
  Preview.11 的冷读失败：冷存活者的 GET 是 0/N。就绪 503 是单独的失败。
- `large-object-get.json` — `expected_len`、`actual_len`、
  `expected_sha256`、`actual_sha256`。正文变短则失败。
- `warp-compare.json` — `current_ops`、`baseline_ops`。默认回归阈值是
  `RUSTFS_WARP_REGRESSION_PERCENT=20`。
- `upgrade-stability.json` 和 `upgrade-rollback.json` — 对象、分片、
  版本、lifecycle 和策略布尔值，加上 `client_errors`、`error_threshold`、
  `rollout_probe_failures` 和 `rollout_error_threshold`（默认 10，用
  `RUSTFS_UPGRADE_ROLLOUT_ERROR_THRESHOLD` 覆盖）。回滚还需要
  `rolled_back: true`。脚本先部署 `RUSTFS_PREV_IMAGE`，写入数据集，再
  滚动到 `RUSTFS_IMAGE`。两个镜像都需要 operator 注解
  `operator.rustfs.com/runtime-default-image-ack`。脚本等到每个 Pod
  都跑目标镜像。单独的 `kubectl rollout status` 不是信号。
- `lifecycle-rule.json` — `rule_accepted`、`listed_enabled`、`get_matches`。
- `expand-status.json` — `pools_before`、`pools_after`、`integrity_ok`。
- `decommission-status.json` — `complete: true`。
- `rebalance-status.json` — `stopped`、`integrity_ok`。
  这些目录场景仍为 Planned 时，缺文件是 `SKIP-planned`。文件存在则打分。
- `disk-full-fill.json` — `enospc_observed`、`reads_ok`、`recovered`。
  填充量限制在该文件系统的剩余空间内，退出时删除。local-path、hostPath，
  或设备号与 `/` 相同的卷，是 `SKIP-unsafe-shared-fs`，不算通过。
- `volume-remount-ro.json` — `remounted_ro`、`writes_rejected`、`reads_ok`、
  `restored`。
- `dm-error.json` — `table_has_error_target`、`read_failed_during_fault`、
  `recovered`，或者一个 `skip` 字符串。生产者用 `nsenter` 跑宿主机
  `dmsetup`。它写入并 fsync 一个 4096 字节的 marker，用
  `dmsetup suspend --nolockfs`、`load`、`resume` 切换表（每一步都检查
  退出码，resume 的错误不会被忽略），丢掉宿主机页缓存，再用
  `dd iflag=direct` 读取。这次读必须失败。装上 error target 之前，生产者
  会 `sync`；有 `fsfreeze` 时冻结再解冻该挂载，有 `blockdev` 时执行
  `--flushbufs`。两者都不存在时不装入 error target。故障期间丢掉页缓存，
  但不再 `sync`，避免把未提交的日志写到 error target 上。恢复是同样的 suspend/load/resume，回到保存的原表。
  error target 看的是 `dmsetup table` 的目标类型字段，行尾空格不会把它
  判成未注入。只有 marker 能读回、删除 marker 成功、挂载选项是读写
  （`errors=remount-ro` 不算只读）、新文件能写入并 fsync 再用 `O_DIRECT`
  读回，并且文件系统检查为干净时，`recovered` 才为 true。没有其他持有者
  时总会卸载，对 ext 执行 `e2fsck -fy`（`dumpe2fs -h` 必须是
  `Filesystem state: clean` 且没有 `needs_recovery`），对 XFS 执行
  `xfs_repair`，然后重新挂载。检查失败也会重新挂载。EXIT trap 总会写出
  `dm-error.json`。如果开始时实验路径是该 dm 设备的精确挂载，trap 在退出
  前会把它重新挂上，表恢复失败时也一样；如果 `fsfreeze` 还冻着，会先解冻。
  挂载检查用 `findmnt --mountpoint`，不会向上走到父文件系统。门禁自己创建并删除 1Gi 的 PV `rg-dm-error-pv` 和 PVC
  `rg-dm-error-claim`（`volumeName` 把 claim 钉在这个 PV 上）。它不会绑定
  四个 100Gi 静态 PV 中的任何一个。写 marker 之前，该路径必须是
  `/dev/mapper/$DM_NAME` 的精确挂载。该路径的 PV 处于 Bound、设备还有别的
  挂载、open count 大于 1（宿主机挂载本身算 1），或者该设备的
  major:minor 出现在 PID 1 以外的挂载命名空间（`/proc/*/mountinfo`，包括
  hostPath Pod）时，结果是 `SKIP-dm-in-use`，不算通过，也不会卸载这个卷。
  `master:N` 等于宿主该挂载 `shared:N`、且挂载点就是该路径或其子目录的
  slave 不是占用者：systemd 服务收到的是这种副本，宿主卸载时它们会一起
  消失。`kubepods` cgroup 里的进程仍然是占用者，包括以相同 `master:N`
  传播进来的 hostPath。扫描把 `in-use`、`clear` 或 `error` 打到 stdout
  并以 0 退出。
  在选中的 `dm-run` 之前和
  之后，如果故障 Tenant 的 pool 或其 PVC 使用
  `RUSTFS_RELEASE_GATE_DM_STORAGE_CLASS`，门禁会删除这个 Tenant，只删除
  故障命名空间里认领该类 100Gi PV 的 PVC，等到这些 PV 不再 Bound，再去掉
  Released PV 的 `claimRef`，并清空本地路径，但保留 `lost+found`。清空某一个
  PV 失败不会跳过其余 PV，也不会清掉该 PV 的 `claimRef`；循环结束后
  命令仍以非零退出。它不删除命名空间。`dm-run` 启动前就判定的 `SKIP-dm-topology` 不会删除 Tenant。
  未选择 device-mapper 时是 `SKIP-no-dm`。选中的场景缺少 dm-run 环境或
  `RUSTFS_RELEASE_GATE_DM_STORAGE_CLASS` 时是 `SKIP-no-dm-device`
  （不算通过）。该存储类的 provisioner 必须是
  `kubernetes.io/no-provisioner`，并且只传给这一次 `dm-run`。其他场景
  继续使用 `RUSTFS_FAULT_TEST_STORAGE_CLASS` 里的动态存储类。其余 DM
  场景是 `SKIP-dm-not-selected`。不要把 8 个 DM 场景背靠背跑完。
  `dm-flakey` 要求 DM 节点上恰好有一个 RustFS Pod。只有一台 Ready 节点，
  或者 `RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false` 且 Pod 数不是
  1 时，结果是 `SKIP-dm-topology`，不算通过。故障命名空间缺少
  `pod-security.kubernetes.io/enforce=privileged` 仍然是失败。
  `docs/DM_FLAKEY.md` 还要求标签 `app.kubernetes.io/managed-by=s3chaos`
  和注解 `rustfs.com/fault-test-tenant`。
- `fresh-install.json` — `health` 和 `live` 为 200。`image_matches`
  出现且为 false 时该用例失败。实跑时这个文件在发布镜像部署之后写出。
- `rustfs-version.txt`、`rustfs-image-libc.txt`、`rustfs-ldd.txt`、
  `rustfs-ldd-musl.txt`、`rustfs-otool.txt`。`ldd` 行 `lib => not found`
  使 dynamic-deps 以 `missing: lib` 失败。每个 ldd 文件单独打分。

`scripts/release-gate-evidence.sh` 在实跑集群上写 fresh-install、大对象、
lifecycle、quorum-edge 和 dm-error JSON。quorum-edge 探针在 PodChaos
之前创建并检查 `mc` alias，等到受害者不再 Ready，再用 `mc cat` /
`mc pipe` 打这些 alias。探针文件放在制品目录下，退出时删除。alias 或
客户端错误在写出任何探针 JSON 之前退出。S3 503 被记录下来，不当成工具
失败。`scripts/release-gate-upgrade.sh` 写升级 JSON。`deploy` 只把
Tenant 滚到 `RUSTFS_IMAGE`。安装了 `warp` 时，`--host` 是去掉 scheme 的
端点（https 再加 `--tls`）。warp 失败或没有 obj/s 数字时不写
`warp-compare.json`，warp 用例单独失败；升级 JSON 仍然写出。
`scripts/release-gate-host-disk.sh` 把专用卷填到 ENOSPC，或把它重挂载为
只读。两个磁盘脚本都不用 IOChaos。退出码 1 是检查失败或配置错误。
退出码 2 是 `SKIP-no-privileged`，仍然是门禁失败。退出码 3 是共享
文件系统拒绝。

## CI amd64

`.github/workflows/release-gate.yml` 在 `workflow_dispatch`、
`repository_dispatch` 类型 `rustfs-release`，以及每天检查最新
`rustfs/rustfs` release 时运行。默认作业下载 Linux 资产并规划所选层级。
`run_kind=true` 启动 kind、安装 Chaos Mesh 2.8.3，并且只有在 RustFS
Tenant CRD 已经安装时才实跑该层级。amd64 runner 可以跑 IOChaos；arm64
chaos-daemon 镜像不能。

派发载荷：

```json
{"version":"1.0.1-preview.11","prev_version":"1.0.0","tier":"standard","dry_run":"false"}
```

## Mac Mini arm64

自托管 Mini 上的 full 层级：

1. OrbStack 或 Lima Ubuntu、k3s、Chaos Mesh 2.8.3、RustFS operator，以及
   用该 release 构建的 Tenant 镜像。
2. 单节点集群必须把 Pod 放在一起：

```bash
export RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false
export RUSTFS_FAULT_TEST_TENANT_UNSAFE_BYPASS_DISK_CHECK=true
export RUSTFS_RELEASE_GATE_ARCH=aarch64
export RUSTFS_RELEASE_GATE_TODA=0
export RUSTFS_RELEASE_GATE_HAS_CLUSTER=1
export RUSTFS_RELEASE_GATE_HAS_DM=0
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_PREV_VERSION=1.0.0 \
  RUSTFS_IMAGE=rustfs-local:1.0.1-preview.11 \
  RELEASE_GATE_TIER=full \
  RELEASE_GATE_DRY_RUN=0
```

`RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false` 选择至少一台 Ready
节点。只有这个默认值不对时才设置 `RUSTFS_FAULT_TEST_MIN_NODES`。
未设置 `RUSTFS_RELEASE_GATE_HAS_DM=1` 时，device-mapper 行保持
`SKIP-no-dm`。设置之后，缺少 dm-run 环境是 `SKIP-no-dm-device`，不算通过。
单节点 Mini，或者未打散且 Pod 数不是 1 的 Tenant，无法让 DM 节点上恰好
有一个 RustFS Pod。选中的 DM 场景此时是 `SKIP-dm-topology`，门禁仍然失败。
要通过 `dm-flakey`，需要多于一台 Ready 节点并保持 Pod 打散的默认值，或者
使用只有一个 Pod 的 Tenant。跑之前按 `docs/DM_FLAKEY.md` 给故障命名空间
打标签：

```bash
kubectl label namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  app.kubernetes.io/managed-by=s3chaos \
  pod-security.kubernetes.io/enforce=privileged \
  --overwrite
kubectl annotate namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  "rustfs.com/fault-test-tenant=${RUSTFS_FAULT_TEST_TENANT}" \
  --overwrite
```

缺少 privileged 标签是检查失败，不是 `SKIP-dm-topology`。
直接的 `network-loss` 使用 80% 丢包。发布门禁还会设置
`RUSTFS_RELEASE_GATE_NETWORK_LOSS_SCOPE=all`（源选择器为 Chaos Mesh
`mode: all`）和 `RUSTFS_FAULT_TEST_NETWORK_LOSS_MIN_PERCENT=10`。
该用例只有在故障窗口内至少 30 次尝试、且错误率不低于该百分比时才通过。
安静的样本是失败。未设置该环境时，其他运行仍使用原来的“任意一次中断”
检查；套件 YAML 里的 `lossPercent` 保持原值。IOChaos 和 TimeChaos 在
Apple Silicon 上仍然跳过。1.0.1-preview.11 上预期
`quorum-edge-cold-read` 失败。`quorum-edge-readiness` 是单独一行。

`s3chaos` 可以在 macOS 上编译：`openat2` 和 `major`/`minor` 仅 Linux
可用，其他目标失败关闭。Mac 上跑的是制品检查（`--version`、`ldd`、
`otool -L`）。这并不让存储恢复辅助程序在 macOS 上改卷。

如果 `git pull` 没有更新发布门禁分支，远端 fetch refspec 可能只包含
`main`。请显式抓取该分支，例如
`git fetch origin cursor/release-gate-2e6e`。

第一个场景之前，以及一次失败的 IOChaos 之后，`make fault-cleanup` 清掉
卡住的 IOChaos 和 PodIOChaos finalizer，避免下一个场景继承故障。S3
用的端口转发如果在 Tenant 仍在启动时退出，会被换掉，包括
`pod-crash-versioned-hot` 和 `rolling-restart-all` 之后。
