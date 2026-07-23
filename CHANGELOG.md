# Changelog

这个文件用来回答三个长期维护问题：

1. **这个仓库最近加了什么？**
2. **当前稳定基线是哪一版？**
3. **本地研究主线是怎么一步步推进到现在的？**

> 说明：这个 GitHub 私有仓库本身是从本地工作树导出的去敏快照，所以时间线分成两层：
>
> - **导出前的本地研究里程碑**
> - **导出后的 GitHub 仓库维护记录**

---

## [Unreleased]

### Planned

- 继续按统一模板沉淀新实验记录。
- 如果后续出现新的稳定里程碑，优先先更新 `CHANGELOG.md` / `docs/decision-log.md`，再决定是否单独打 tag / release。

## [2026-07-23-wpp-wps-f0-f3-source-retention]

### Added

- 新增 `research/wps-krpt-proxy/`，保存 WPP/WPS `krpt.dll` 代理层源码、导出转发脚本和构建入口。
- 更新 `research/memory-loader-lab/` 到 WPP/WPS 最终候选对应的 loader、packer 和 profile DLL 构建源码。
- 更新 `AdaptixServer/extenders/direct_https_agent/` 到 `72e54ef` 对应的 direct_https 命令输出、任务清理和协议测试代码。
- 新增 `docs/evidence/2026-07-21-wpp-wps-f0-ps-encoding/`，保存中文实现说明、WPS DLL 到 Agent 的详细调用链、三次部署摘要和主要文件哈希。

### Changed

- 将研究构建脚本中的本地绝对路径改为仓库根目录推导或环境变量输入。
- 将测试代码中的固定探测地址改为 `DIRECT_HTTPS_PROBE_HOST` 编译宏，默认值为本地占位地址。
- 补齐 direct_https Go 依赖的 `go.mod` 校验记录，使全新模块缓存下的测试准备过程可复现。
- 保持仓库的 source-only / doc-first 规则，最终 `dll/dat/bin/so` 继续由本地候选目录和 SHA-256 清单留存。

### Verification

- WPP/WPS 三次独立新鲜部署：`17/17` 全矩阵。
- F0 主命令检查：每次 `10/10`。
- disks：WPP/WPS 均 `2/2`，与靶机实际驱动器匹配。
- upload/download：内容和 SHA-256 匹配。
- 新鲜 Qscan：三次 detected `0`、errors `0`。
- Go 协议测试：`go1.25.4` 下 `go test ./...` 通过。

---

## [2026-07-01-research-ops-docs]

### Added

- 新增 `docs/research-roadmap.md`
- 新增 `docs/experiment-template.md`
- 新增 `docs/decision-log.md`

### Changed

- 更新 `README.md`，把路线图、实验模板、决策日志纳入长期维护导航。

### Purpose

- 让后续研究不只“有结果”，而且“有过程”。
- 让新实验可以按统一模板记录，减少遗漏：
  - 实验目标
  - 假设
  - 改动点
  - 构建动作
  - 样本 hash
  - 证据路径
  - 结论与下一步
- 让关键架构/流程决策不再散落在聊天和临时文档里。

---

## [2026-06-30-docs-maintenance]

### Added

- 新增 `CHANGELOG.md`
- 新增 `docs/repo-map.md`
- 新增 `docs/build-matrix.md`
- 新增 `docs/binary-release-policy.md`

### Changed

- 扩展 `README.md`，让仓库更像一个长期维护的私有研究仓库，而不只是一次性导出快照。

### Purpose

- 让自己以后回看时，能快速知道：
  - 研究现在走到哪一步了
  - 哪些文件是干什么的
  - 改哪一层代码之后要不要重编 / 重启 / 重新生成
  - 哪些二进制可以放 release，哪些不能

---

## [baseline-2026-06-30]

### Added

- 导出一个去敏后的私有 GitHub 研究快照
- 新增去敏 README、研究总结、构建链说明、证据摘要、源基线说明
- 创建 GitHub release：`baseline-2026-06-30`

### Included

- `AdaptixServer/extenders/direct_https_agent/`
- `research/memory-loader-lab/`
- `scripts/`
- `docs/`

### Excluded

- `dist/`
- `reports/`
- Windows 落地样本
- 本地构建产物
- 本地 API 密码、token、私钥、绝对路径、实验内网地址

### Goal

- 固化一个**可阅读、可追溯、可继续整理**的源码与文档基线。

---

## 导出前的本地研究里程碑（摘要）

这一部分不是 GitHub 仓库自身的 commit 历史，而是这次导出快照对应的本地研究主线，用来提醒自己“这版东西为什么值得保留”。

### 2026-06-27：PE header 痕迹问题被正式拆开

- 开始把“内存里是否还能看到明显 PE 特征”变成可验证问题。
- 研究重点从“只是能不能上线”推进到“上线后内存长什么样”。

### 2026-06-28：引入 DHPL1 / profile-only loader 思路

- 从“完整 DLL 直接包起来再加载”转向“先离线提取最小必要元数据，再在运行时映射”。
- 这一节点的重点，是让 loader 更偏向专用 payload loader，而不是通用 PE loader。

### 2026-06-29：外层容器从 XOR 演进到 AES-GCM，再到 DHPLE2

- 外层容器保护从简单 XOR 演进到更正式的认证加密方案。
- 进一步加入 `PBKDF2 + salt + AES-256-GCM` 这一代方案。
- 研究视角从“能跑”进一步转向“结构和材料是否更合理”。

### 2026-06-30：本地稳定基线固化

- 本地形成 `local-baseline-2026-06-30-profile-loader-dhple2`
- 对应本地基线 commit：`4676edf`
- 随后导出为当前这个私有 GitHub 快照仓库

---

## 建议维护方式

以后每次你觉得“这轮研究到了一个值得保存的稳定节点”，建议至少做这 3 件事：

1. 在本地先确认可运行或可解释的基线
2. 更新本文件 `CHANGELOG.md`
3. 再决定是否：
   - 打本地 tag
   - 导出新的私有快照
   - 或更新当前 GitHub 私有仓库
