# 研究路线图（research roadmap）

这份文档回答的是：

> **接下来这个私有研究仓库，还准备沿着哪些方向继续推进？**

它不是“必须按顺序完成的死板待办清单”，而是一个**长期路线图**。  
作用是防止后续研究重新变成：

- 只记得眼前一个问题
- 做完一轮实验后，不知道下一轮该往哪条线压缩
- 同一个问题反复重复试，而没有沉淀成阶段路线

---

## 1. 当前基线

当前仓库对应的稳定研究基线是：

- 本地基线 tag：`local-baseline-2026-06-30-profile-loader-dhple2`
- GitHub 私有仓库导出基线：`baseline-2026-06-30`

当前已经完成的核心工作：

1. `direct_https` 结构与构建链梳理
2. `profile-only loader` 方向的实现与保留
3. 外层容器从 XOR 演进到 `PBKDF2 + salt + AES-256-GCM`
4. PE header 痕迹问题进入结构性处理阶段
5. 私有仓库完成基本去敏与长期维护文档化

---

## 2. 后续路线总览

当前建议把后续工作分成 5 条主线：

| 主线 | 关注点 | 当前状态 |
|---|---|---|
| A. 研究记录规范化 | 把实验记录、决策记录、阶段总结固定下来 | 已起步 |
| B. 构建/复现稳定性 | 减少“改了但没生效”“这次不知道用了哪个样本”的问题 | 进行中 |
| C. loader / container 演进 | 继续压缩运行期结构暴露面 | 进行中 |
| D. 运行形态与内存痕迹 | 继续观察映射后还有哪些明显材料 | 进行中 |
| E. release / 仓库治理 | 让 GitHub 私有仓库适合长期使用 | 已起步 |

---

## 3. 分主线说明

### A. 研究记录规范化

#### 目标

让每一轮研究都至少留下三种记录：

1. 这轮想验证什么
2. 这轮实际改了什么
3. 这轮得出了什么结论

#### 当前已具备

- `CHANGELOG.md`
- `docs/repo-map.md`
- `docs/build-matrix.md`
- `docs/binary-release-policy.md`
- `docs/experiment-template.md`
- `docs/decision-log.md`

#### 下一步建议

- 后续每次新实验，单独新建一份实验记录文件
- 关键架构变化，额外在 `docs/decision-log.md` 追加一条决策记录

#### 完成标准

- 以后每一轮实验都能回答：
  - 为什么做
  - 改了哪层
  - 样本 hash 是什么
  - 证据在哪
  - 结论是什么

---

### B. 构建/复现稳定性

#### 目标

降低下面这类问题出现的概率：

- 代码改了，但跑的不是新样本
- loader 改了，但 payload/container 没更新
- Go 层改了，但 runtime 还是旧的
- Windows 还在跑旧落地文件

#### 当前已具备

- `docs/build-matrix.md`
- 自动化脚本：
  - `scripts/regenerate-direct-https-agent.sh`
  - `scripts/run-mmpp-powershell-loader-test.sh`
  - `scripts/run-profile-only-loader-test.sh`

#### 下一步建议

- 把“记录 hash”和“记录运行样本路径”作为每轮实验默认动作
- 在实验记录中固定写：
  - loader sha256
  - container sha256
  - Windows 落地目录

#### 完成标准

- 每次回头看实验记录时，都能明确知道当时到底测的是哪一版材料

---

### C. loader / container 演进

#### 目标

继续把 loader/container 这条线做得更专用、更清楚：

- 哪些信息一定要在运行期存在
- 哪些信息可以在 packer 阶段提前算好
- 哪些信息不必保留成完整 PE 形态

#### 当前已具备

- `profile-only loader`
- `DHPL1`
- `DHPLE2`
- `PBKDF2 + salt + AES-GCM`

#### 下一步建议

- 继续梳理容器字段的最小必要集合
- 区分：
  - 运行必需元数据
  - 调试方便元数据
  - 可进一步削减的元数据

#### 完成标准

- 对容器中的每一类字段，都能回答“为什么必须存在”

---

### D. 运行形态与内存痕迹

#### 目标

继续围绕这个问题推进：

> **映射完成后，内存里还剩下哪些明显结构痕迹？**

#### 当前已具备

- PE header 痕迹相关实验
- 内存扫描辅助脚本
- 对 expected base / MZ / PE / header 区域的观察思路

#### 下一步建议

- 继续把“看见问题”变成“有固定观察表”的问题
- 以后新实验默认补：
  - expected base 是否有 MZ/PE
  - header 前 16 字节是什么
  - section 名是否还能明显识别
  - 是否存在长期 RWX

#### 完成标准

- 后续每轮 loader 相关实验都能复用同一套内存形态检查项

---

### E. release / 仓库治理

#### 目标

让这个 GitHub 私有仓库长期保持：

- 好找
- 好读
- 好回溯
- 不误传环境绑定材料

#### 当前已具备

- `README.md`
- `CHANGELOG.md`
- `docs/repo-map.md`
- `docs/binary-release-policy.md`
- 文档型 release 资产

#### 下一步建议

- 如果后面再打 release，优先继续走 source-only / docs-first
- 二进制资产先经过 allowlist/denylist 检查

#### 完成标准

- 以后每次发 release，不需要重新从头判断哪些文件能传

---

## 4. 推荐执行顺序

如果下一阶段你想继续稳定推进，建议优先顺序是：

1. **先把研究记录规范化**
2. **再把构建/复现稳定性做扎实**
3. **再继续压 loader/container 本身**
4. **然后继续盯内存痕迹**
5. **最后同步更新仓库与 release**

原因很简单：

- 如果前两步没做好，后面实验再多，也容易混乱
- 如果前两步做好了，后面每次实验都会更省时间

---

## 5. 如何使用这份路线图

建议每次开始新一轮实验前，先做 3 件事：

1. 看一眼这份路线图，确认这轮属于哪条主线
2. 用 `docs/experiment-template.md` 建一份新实验记录
3. 如果这轮改动会影响长期策略，再更新 `docs/decision-log.md`

这样这个仓库就会越来越像一个有持续演进脉络的研究仓库，而不是一堆零散文件。

