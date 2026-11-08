# ARTEX 凭据泄露修复与部署迁移（2026-11-08）

本说明对应 `firedfox/ARTEX` 的会话绑定、执行边界和部署权限修复。**合并代码、更新镜像均不会替已部署实例轮换泄露过的密钥或数据库密码。** 完成下述维护和验收后，才能把实例标为已修复。本文不含报告中的密钥、密码、令牌或生产地址。

## 修复范围与功能变化

报告中的直接读取证据具有“已能在 ARTEX 容器内以 root 执行命令”的前提；这不等于已经证明未登录的公网访问者可以远程执行命令。但把模型控制的 Bash、Python、MCP、任意文件工具与签名密钥、数据库凭据放在同一个进程权限域中，会让工具执行自然跨入管理权限，必须消除这种结构。

本版本先将控制面封闭，而非声称已经实现完整沙箱：

| 项目 | 本版本行为 |
|---|---|
| 登录 | HS256 签名、严格 claims 验证与数据库中真实签发的完整令牌 SHA-256 记录同时成立才放行；有效期 12 小时 |
| 只有 JWT 签名密钥 | 无法自行制造未签发会话；旧版无数据库记录的 JWT 一律失效 |
| 退出、改密码 | 退出撤销当前会话；改密码/离线密码重置撤销全部会话；与并发登录之间由事务和行锁保证顺序 |
| 换签名密钥 | 仅离线维护命令可以显式激活；启动时密钥与数据库不一致即拒绝，旧进程不能把旧密钥重新激活 |
| 数据库故障 | 已认证接口返回 503，不退回只验证 JWT；匿名健康检查不暴露服务版本 |
| 主动执行 | Bash、交互 shell、Python、自定义命令/HTTP、所有 MCP transport、ScopeSentry、Noa 文件工具、模型任意文件读写、网页搜索探测暂停；新建及恢复会话均经统一边界 |
| 人工文件管理 | 工作区、技能和聊天上传走已打开的根目录句柄，拒绝穿越和指向根外的符号链接；密钥目录不能位于工作区或技能目录内 |
| 保留能力 | 管理界面、历史结果、领域数据库工具、文字讨论、管理员人工文件管理。恢复任务仍可能进行模型推理，但不能恢复被暂停的执行工具 |
| 容器 | UID/GID 10001、只读根文件系统、删除 capabilities、禁止提权；控制面镜像不再附带扫描器、浏览器或 Python 工具链 |
| PostgreSQL | 独立应用角色；启动前拒绝 superuser、CREATEDB、CREATEROLE、REPLICATION、BYPASSRLS，以及可达的服务器文件/程序执行角色 |

只读 secret mount 只阻止写入，不能阻止同 UID 的工具读取；改成非 root 也不会隔离同 UID 的代码。KMS 可以减少密钥落盘，但如果任意代码仍能调用管理面的签名接口、访问其凭据或修改会话数据库，也不能独自解决权限隔离。本版本没有允许跳过执行边界的环境变量或前端开关。

上游 v0.5.1 的登录限速、trusted proxy、独立 key 目录与密码约束已选择性纳入；这些改动本身不提供持久会话撤销或执行隔离。源码依据：[上游 v0.5.1](https://github.com/BaaRai/ARTEX/releases/tag/v0.5.1)、[上游安全说明](https://github.com/BaaRai/ARTEX/blob/v0.5.1/CHANGELOG.md)。

## 1. 新部署

从包含本修复的确定提交构建，不要用版本字符串 `dev` 判断镜像是否包含修复。旧 `install.sh` 自动复用数据库管理员身份，不适用于本版本；使用以下明确的 Compose 流程。运行 Docker 的账户本身须是可信维护者。

### 1.1 生成独立凭据，写入私有文件

以下脚本只适用于没有 `.env` 的新部署。它把新密码直接写入 mode 0600 的文件，不输出密码，也不覆盖已有配置。两种数据库身份独立：`artex_admin` 是 PostgreSQL 的维护管理员；`artex_app` 是应用登录身份。

```bash
python3 - <<'PY'
import os, secrets
from pathlib import Path
from urllib.parse import quote

admin = secrets.token_hex(32)
app = secrets.token_hex(32)
replacements = {
    'POSTGRES_USER': 'artex_admin',
    'POSTGRES_PASSWORD': admin,
    'ARTEX_APP_PASSWORD': app,
    'ARTEX_PG_DSN': 'postgres://artex_app:' + quote(app, safe='') + '@postgres:5432/artex?sslmode=disable',
}
lines = Path('.env.example').read_text().splitlines()
for i, line in enumerate(lines):
    name = line.split('=', 1)[0]
    if name in replacements:
        lines[i] = name + '=' + replacements[name]
fd = os.open('.env', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, 'w') as f:
    f.write('\n'.join(lines) + '\n')
    f.flush()
    os.fsync(f.fileno())
print('Created private configuration; no credentials were printed.')
PY
```

`.env` 中的 `ARTEX_APP_PASSWORD` 仅传给 PostgreSQL 新卷初始化脚本；运行 ARTEX 的容器只收到 `ARTEX_PG_DSN`，不会收到管理员密码。URL 中的用户名和密码需要百分号编码；不要直接拼接包含 `@`、`:`、`/` 或 `#` 的密码。Compose 的 `sslmode=disable` 仅用于同一受控 Docker 网络中的本地 PostgreSQL；远程数据库应按其证书配置 TLS。

### 1.2 准备明确的挂载目录

先检查 `data`、`keys`、`skills` 是本部署预期的实际目录，不是指向其它位置的链接。以下命令用于新部署；已有数据必须先走后面的迁移流程。

```bash
sudo install -d -o 10001 -g 10001 -m 0700 data keys
sudo find -P skills -xdev -type d -exec chown 10001:10001 {} +
sudo find -P skills -xdev -type f -exec chown 10001:10001 {} +
docker compose config --quiet
docker compose up -d --build
```

`scripts/bootstrap-postgres.sh` 只在 PostgreSQL **全新空卷**初始化时执行：创建固定的非特权 `artex_app`，授予目标库 CONNECT 及 public schema 的必要建表权限。应用自行拥有它随后创建的表、序列和函数，满足当前每次启动自动 DDL/seed 的需要。脚本不会降权、改密码或复用已存在的同名角色。

进入 HTTPS 管理入口完成首次设置。一次性 setup token 只在本机私有日志中查看，不上传日志到公共 issue/PR。不要为省事把 8787/8788 端口直接暴露公网；保留默认 loopback 发布地址，使用已有的 HTTPS 反向代理。

## 2. 已有部署：停机、留证、准备权限迁移

1. 确认完整部署拓扑：所有 ARTEX 副本、Docker volume/bind mount、独立数据库、反向代理，以及可能恢复旧进程的 systemd/定时任务。只停一个副本不足以完成换钥。
2. 暂停所有 ARTEX 实例及自动拉起任务，保持 PostgreSQL 可用于维护。Compose 部署先运行 `docker compose stop artex`。
3. 在仅维护者可读的目录备份数据库、原镜像 digest、原配置和密钥、文件 owner/权限清单。保留报告和可能的入侵证据，先不要运行清理命令。备份目录不能挂入 ARTEX 的工作区或技能目录。
4. 盘点泄露窗口内的登录、任务、工具、配置、数据库角色与授权变化。报告已明确暴露的 JWT key 和数据库密码必须更换；其它可被原执行环境读取的 LLM/API/MCP 凭据应逐项确认并轮换。切勿把任何真实值写入 PR、命令行参数或聊天记录。

### 2.1 迁移旧的 root 文件所有权

新镜像不会在启动时递归 `chown`。先用 `find -P` 检查链接、挂载边界、UID/GID 分布，并保留 owner/ACL 备份。仅对确认属于该 ARTEX 实例的实际目录及其预期旧 UID 执行有界迁移。例如，**只在旧数据确实归 UID 0 所有时**：

```bash
# 先审阅数量和路径；不要对 /、/opt 或整个宿主机执行此操作。
sudo find -P data keys skills -xdev -uid 0 \( -type f -o -type d \) -print
# 确认上面的范围后再执行；不跟随符号链接，不跨挂载点。
sudo find -P data keys skills -xdev -uid 0 \( -type f -o -type d \) -exec chown 10001:10001 {} +
sudo chmod 0700 data keys
sudo chmod 0600 keys/jwt.key
```

如果旧 UID 不是 0，用审阅确认的 UID 替代；如果有不同 owner、ACL、外部挂载或链接，逐项处理，不做全目录无条件改写。校验 skills 中目录可搜索、文件可读写，应用的 key 目录必须独立于 data 和 skills 的真实路径。回滚 owner 应使用维护前保存的清单，而非猜测原 UID。

### 2.2 数据库角色迁移

不要直接把现有 PostgreSQL bootstrap superuser 降为普通用户，也不要使用 `REASSIGN OWNED BY ...`：该语句会涉及当前库的全部对象以及共享数据库/tablespace 所有权，范围超出 ARTEX。[PostgreSQL 16 官方说明](https://www.postgresql.org/docs/16/sql-reassign-owned.html)

在可信维护终端通过 `.pgpass`/交互密码等私有方式连接，明确选择 **ARTEX 专用目标库**。保持独立维护管理员，创建新的 `artex_app`，先禁用登录并限制角色属性，再通过 psql `\password artex_app` 设置随机密码，最后启用登录。`\password` 在客户端产生 SCRAM 验证数据，可避免把明文密码写入 SQL 命令历史。

```sql
CREATE ROLE artex_app NOLOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
SET password_encryption = 'scram-sha-256';
\password artex_app
ALTER ROLE artex_app LOGIN;
```

若同名角色已存在，不运行上述语句：先审阅其属性、成员关系与用途。不要悄悄修改可能由其它应用使用的角色。新应用密码与泄露过的数据库密码必须不同。

迁移脚本默认仅生成计划并回滚，明确校验目标库、旧 owner、已知 ARTEX 表/函数/附属序列和索引。遇到未知对象、外部 schema、陌生 owner 或保留名称冲突即拒绝；先调查归属，不要为通过脚本而删除这些检查。

```bash
# psql 连接参数由维护者按实际主机配置；不要在命令参数内填写密码。
psql -X -v ON_ERROR_STOP=1 -d artex \
  -v expected_database=artex -v previous_owner=artex_admin \
  -f scripts/migrate-runtime-role.sql

# 审阅计划后，应用同一限定范围。
psql -X -v ON_ERROR_STOP=1 -d artex \
  -v expected_database=artex -v previous_owner=artex_admin \
  -v apply_migration=yes -f scripts/migrate-runtime-role.sql
```

示例 `previous_owner=artex_admin` 必须替换为查询确认的旧对象 owner。该脚本不修改其它数据库、tablespace 或管理员角色，不迁移 extension 所有对象。应用需要拥有自己的 schema 对象，只有 SELECT/INSERT/UPDATE/DELETE 授权不足以运行当前自动迁移。

随后在私有 `.env`/`config.json` 更新运行 DSN 为 `artex_app`，轮换已泄露的旧数据库身份密码，并同步其它确认仍需该身份的维护组件；单独修改 Compose 环境变量不会修改已有 PostgreSQL volume 中的角色密码。审阅角色成员关系，确保 runtime 无法切换至高权限角色。服务器文件/程序执行角色的危害见 [官方预定义角色说明](https://www.postgresql.org/docs/16/predefined-roles.html)。

**数据库改密码不会断开已经认证的连接。** 先验证独立维护身份确实可用，再盘点并终止泄露身份在**所有数据库**中的旧 backend，而不只是目标 ARTEX 库的连接。维护脚本的连接检查只是当时的快照，不能替代持续停机与这一步操作。以下在新维护身份下执行，`old_compromised_role` 替换为已经确认的泄露角色名称，先审阅查询结果，再终止：

```sql
\set leaked_role 'old_compromised_role'
SELECT pid, datname, usename, application_name, client_addr
FROM pg_stat_activity WHERE usename = :'leaked_role';
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE usename = :'leaked_role' AND pid <> pg_backend_pid();
```

还要审计其它新建角色/授权、PG 主机程序执行及持久化。如果证据表明容器、宿主机或 PostgreSQL 已实际遭到篡改，应从可信镜像和经审阅的备份重建；修改目录 owner、换密码和删会话不能清除未知持久化。本文没有执行生产轮换、连接终止或重建，这些必须在维护记录中单独确认。

## 3. 显式换 JWT 密钥与撤销会话

先用本修复的确定提交构建 `docker compose build artex`。整个过程保持所有 ARTEX 服务停止。以下命令只启动一次性维护进程，不启动 API 服务；默认仅验证，`--apply` 才修改。

### 3.1 生成候选密钥

```bash
docker compose run --rm --no-deps --entrypoint /app/artex-security artex \
  prepare-key --key-file /app/keys/jwt.key.next \
  --data-dir /app/data --skills-dir /app/skills

docker compose run --rm --no-deps --entrypoint /app/artex-security artex \
  prepare-key --key-file /app/keys/jwt.key.next \
  --data-dir /app/data --skills-dir /app/skills --apply
```

目标必须不存在；生成采用随机 256 bit 材料、O_EXCL、0600，并同步文件及目录项。该操作不修改当前 key 或数据库。候选文件已存在时不会覆盖，应先查清它是否来自上次未完成的轮换。

### 3.2 原子替换文件，再显式激活

原 key 已按第 2 节备份到容器不可见的私有位置后，在同一 keys 文件系统内替换。不要把旧密钥备份到 data/skills。

```bash
sudo mv -T -- keys/jwt.key.next keys/jwt.key
sudo python3 - <<'PY'
import os
fd = os.open('keys', os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(fd)
finally:
    os.close(fd)
PY

docker compose run --rm --no-deps --entrypoint /app/artex-security artex \
  activate-key --key-file /app/keys/jwt.key \
  --data-dir /app/data --skills-dir /app/skills --database artex

docker compose run --rm --no-deps --entrypoint /app/artex-security artex \
  activate-key --key-file /app/keys/jwt.key \
  --data-dir /app/data --skills-dir /app/skills --database artex --apply
```

命令核对实际连接的数据库名称及运行角色权限，迁移 schema 后在一个事务中更新 key fingerprint、生成新会话世代并删除已签发会话。重复激活同一文件也会撤销所有会话。输出只包含 SHA-256 指纹和成功/失败结果，绝不输出 key 或 DSN。

**故障恢复：** 文件替换后、数据库激活前发生中断时，继续保持停机，核对意图中的新文件，再重复 `activate-key`。数据库与文件不一致时普通启动必然拒绝；不能为恢复服务删除 `auth_state`、自动激活旧文件，或把旧泄露密钥重新装回。维护工具不提供“忽略不匹配继续启动”选项。

只撤销会话而不换文件时可用：

```bash
docker compose run --rm --no-deps --entrypoint /app/artex-security artex \
  revoke-sessions --database artex --apply
```

这不替代泄露后的换钥/换数据库密码。数据库拥有者本来就能修改会话表，所以会话绑定不能补救数据库凭据继续泄露的环境。

### 3.3 忘记管理员密码时的离线重置

`reset-password.sh` 现在只是维护 CLI 的静默输入封装，不接受明文 `-p`、`-W`、`--dsn` 参数，不输出 DSN，也不再通过包含新密码的 SQL 调用 pgcrypto。先停所有实例，在可信终端运行：

```bash
./reset-password.sh --mode docker --database artex
# 本机二进制部署：先构建 artex-security，提供私有 ARTEX_CONFIG 或 ARTEX_PG_DSN。
./reset-password.sh --mode local --database artex --config /private/artex/config.json
```

CLI 对应 `reset-password --database artex --password-stdin [--apply]`，读取 stdin 的原始字节，最多 72 字节、至少 12 个字符，默认仍然只验证。封装脚本两次静默读取输入后显式传 `--apply`。实际修改使用应用端 bcrypt 和数据库 trigger，原子撤销全部已签发会话。

## 4. 重新启动与验收

```bash
docker compose up -d artex
docker compose ps
```

逐项记录结果，不以 `/api/health` 单一 200 作为安全验收：

- 镜像 digest/源码提交是预期修复版本；进程 UID/GID 为 10001，根文件系统只读，capabilities 已删除且 no-new-privileges 生效。只检查指定 inspect 字段，不导出包含密码的完整容器配置。
- runtime 数据库角色没有服务器管理/文件/程序执行权限，也没有可达的高权限成员角色；独立维护管理员仍可使用。
- JWT key 位于独立真实目录，mode 0600；新实例正常登录后，刷新和正常重启保持会话。
- 旧会话返回 401；登出后的同一 token 返回 401；改密码后所有原会话失效；数据库故障时受保护接口 503。仅持有签名 key 的伪造用例应在隔离测试库完成，不携带真实 key 做公网 PoC。
- UI 明确提示控制面模式。直接调用自定义工具、MCP、搜索探测、模型文件/命令等入口仍被后端拒绝；旧任务与旧会话恢复不能带回执行能力。
- 文件及技能正常操作可用，越界链接无法读写；聊天附件使用独占新文件，不覆盖预先放置的文件或链接。

CI 的安全专项使用真实 PostgreSQL 与 Go race detector，拒绝测试跳过和缺失类别；另外保留完整 Go/web 测试和 Compose smoke。测试所用凭据全部是临时合成值。生产验收与现网凭据轮换需要在实际服务器独立记录，CI 不能代替。

## 5. 恢复主动执行的条件

后续需要实现与控制面分离的 runner：独立身份、进程/挂载/PID/网络边界与资源限制，只接收任务所需的最小数据；不挂载控制面 data/keys/config、不传管理数据库 DSN、不暴露 Docker socket 或控制面 `/proc`。授权回调必须把任务和实际签发的会话在服务器端绑定，并限制能力与有效期。还需覆盖 Bash/Python、默认与延迟 SDK 工具、文件工具、MCP stdio/HTTP/SSE、浏览器、插件/Noa、任务恢复和直接 API。

可以评估已有容器/沙箱 runner，但接入之后仍须用恶意任务验证这些边界与混合负载。只有测试通过的独立 runner 才能恢复主动执行；修改布尔变量、挂只读 secret 或换 UID 不满足条件。
