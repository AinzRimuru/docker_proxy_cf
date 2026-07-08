# docker-hub-proxy

基于 Cloudflare Worker 的 Docker Hub **pull-only** 反向代理。通过你自己的域名拉取 Docker Hub 公共镜像。

> 仅支持 `docker pull`（GET/HEAD），不支持 push 等写操作。

## 工作原理

```
docker client ──► 你的 Worker 域名
                     │
                     ├─ /v2/...manifests/tags ──►  registry-1.docker.io  （小文件，Worker 转发）
                     ├─ /token?...              ──►  auth.docker.io       （获取拉取 token）
                     └─ /v2/...blobs/<digest>   ──►  registry-1.docker.io 返回 307
                                                       ↓
                                          改写 Location 为 /redirect_to_<cdn>/...
                                          由 Worker 统一回源 CDN 下载大层
```

关键设计：

- **透明转发 + 仅改写 auth realm**。把 401 响应里 `WWW-Authenticate` 的 `realm` 指回 Worker 的 `/token`，客户端的 token 获取流程自然走代理。客户端拿到的是 `auth.docker.io` 签发的真 token，对 `registry-1.docker.io` 直接有效——无需在 Worker 内签发/缓存 token，匿名与带认证拉取都兼容。
- **blob 下载改写回源**。registry 会把 blob 请求 307 到 CDN（`production.cloudfront.docker.com`）。Worker 不让客户端直连 CDN，而是把 307 的 `Location` 改写回 `/redirect_to_<cdn-host>/...`，由 Worker 自己回源 CDN 并流式返回——所有流量只经过单一代理域名，无需为 CDN 域名单独配置。
- **自动补 `library/`**。`docker pull <域名>/nginx` 会被改写为 `library/nginx`，与官方镜像命名空间一致。
- **仅 pull**。只放行 `GET/HEAD/OPTIONS`，其它方法返回 `405`。

## 部署

### 方式一：Wrangler CLI（推荐）

```bash
npm install
npx wrangler login        # 首次需要登录
npx wrangler deploy
```

部署成功后会得到一个 `https://docker-hub-proxy.<你的子域>.workers.dev` 地址。也可绑定自定义域名（Workers → Triggers → Custom Domains）。

> 本地调试：`npm run dev`，然后 `curl -i http://127.0.0.1:8787/v2/`。

### 方式二：Cloudflare Pages（单文件）

把 `src/index.js` 重命名为 `_worker.js` 直接上传到 Pages 即可（内容无需改动，已是 ES module 默认导出）。

## 启用账号鉴权（绕开匿名限流，推荐）

匿名拉取受 Docker Hub 限流（100/h），而 CF Worker 出口 IP 是全网共享的，匿名额度极易被耗尽导致 `429 TOOMANYREQUESTS`。配置一个 Docker Hub 账号后，Worker 会用该账号统一签发 token，并在转发 registry 时覆盖鉴权——所有拉取计入**账号额度（200/h，不受共享 IP 影响）**，客户端**无需 `docker login`**。直接拉取与 registry-mirror 两种用法都覆盖。

代码只引用变量名（`env.DH_USERNAME` / `env.DH_PASSWORD`），账号信息以 **Worker 加密 secret** 存储，不进源码。

**设置（项目目录下）：**

```bash
# 1) 写入 Docker Hub 账号（格式 用户名:密码，按首个冒号拆分；密码可含特殊字符）
#    强烈建议用 Docker Hub Access Token 代替账号密码
printf '%s' '你的用户名:你的密码或PAT' > dh_creds

# 2) Cloudflare 鉴权：导出环境变量（脚本会优先用它；也可在项目目录放 token 文件，已 gitignore）
export CLOUDFLARE_API_TOKEN='你的CF令牌'

# 3) 把账号写入 Worker secret（读取 dh_creds）
./set-secrets.sh

# 4) 部署 / 更新代码
./deploy.sh
```

完成后 `docker pull <你的域名>/alpine` 直接可用，无需 login。响应头里 `docker-ratelimit-source` 会显示你的账号名、`ratelimit-limit: 200;w=3600`，即代表已走账号额度。未配置 secret 时自动回退为匿名透传模式。

> 该账号额度被所有使用本代理的人共享；凭据建议用专用 Access Token 并在泄露后及时轮换。`dh_creds`、`token` 已在 `.gitignore` 中。

## Token 保护（防真实账号 token 泄露，公开服务推荐）

未启用时 `/token` 会把**真实的 Docker Hub 账号 token** 返回给客户端——服务一旦公开，任何人都能从 `/token` 刮走真 token 直连 Docker Hub 消耗账号额度。启用 token 保护（设置 `PROXY_TOKEN_KEY`）后：

- `/token` 只签发 **proxy token**（HMAC-SHA256 签名的 JWT），**真实账号 token 仅在 Worker 内部使用、绝不外发**。
- registry 要求客户端持有有效 proxy token（标准 Bearer 流程，docker 客户端自动完成 401→取 token→重试）。
- proxy token 对 Docker Hub 无效、签名不可伪造，被刮走也无用。

**设置签名密钥（脚本自动生成 32 字节随机密钥）：**

```bash
# A) 仅 token 保护：任何人可拉取，但拿不到真实账号 token
! ~/DockerProxyCF/set-proxy-key.sh

# B) token 保护 + 访问控制：未知密码者无法拉取
! ACCESS_KEY=你的访问密码 ~/DockerProxyCF/set-proxy-key.sh
! ~/DockerProxyCF/deploy.sh
```

启用后 `docker pull <你的域名>/alpine` 仍无需手动 login（客户端自动完成鉴权流程）。若设了 `ACCESS_KEY`，则需先：

```bash
docker login <你的域名> -u任意用户名 -p<ACCESS_KEY>
```

> `PROXY_TOKEN_KEY` 仅 Worker 内部使用、无需记忆；更换它会使已签发 token 失效（proxy token 默认 1 小时过期，影响很小）。

## 账号池与 429 冷却（D1）

单账号（`DH_USERNAME`/`DH_PASSWORD`）额度耗尽即 429。绑定 D1 后可存**多个账号**，Worker 按 `last_used` 轮询选号；某账号触发 429 自动**冷却 6 小时**（写 `rate_limited_until=now+6h`），期间跳过、自动换下一个；D1 账号全冷却时回退单账号（若有）或返回 429。

**创建 D1 + 建表（一次性）：**
```bash
! ~/DockerProxyCF/d1-setup.sh   # 创建库 docker-hub-accounts + accounts 表，输出 database_id
```
需把返回的 `database_id` 填入 `wrangler.jsonc` 的 `d1_databases` 绑定（binding 名为 `DB`）。

**录入账号**（`accounts.txt` 每行 `用户名:密码`，`#` 为注释；密码建议用 Docker Hub Access Token）：
```bash
! ~/DockerProxyCF/insert-accounts.sh
```

**accounts 表：** `username`、`password`、`enabled`(0/1)、`rate_limited_until`(ms 时间戳，0=可用)、`last_used`、`limited_count`(被 429 次数)。

> D1 有账号则用账号池；D1 为空或查询失败时自动回退单账号。冷却逻辑可隔离验证：`! ~/DockerProxyCF/verify-cooldown.sh`。

## 客户端使用

**直接拉取：**

```bash
# 官方镜像（library/ 可省略）
docker pull <你的域名>/nginx
docker pull <你的域名>/library/nginx:1.27

# 用户仓库
docker pull <你的域名>/user/repo:tag
```

**作为 registry mirror（推荐，无需改镜像名）：**

编辑 `/etc/docker/daemon.json`（Docker Desktop 在设置 → Docker Engine）：

```json
{
  "registry-mirrors": ["https://<你的域名>"]
}
```

重启 Docker：

```bash
sudo systemctl restart docker
# 或 macOS/Windows 重启 Docker Desktop
```

之后 `docker pull nginx` 会自动走镜像。

## 验证

```bash
# 1. 探活：匿名模式返回 401（realm 指向你的域名）；配置账号后返回 200
curl -i https://<你的域名>/v2/

# 2. 完整拉取一个镜像
docker pull <你的域名>/alpine
```

## 限制与说明

- **仅 pull**：所有写操作（push/delete 等）返回 `405`。
- **匿名限流**：匿名拉取受 Docker Hub 速率限制（100/h），且 Worker 出口 IP 共享，极易 `429`。**已配置账号鉴权即不受此限**（见上文「启用账号鉴权」），客户端也无需 `docker login`。
- **上游固定为 `registry-1.docker.io`**，仅代理 Docker Hub，不代理其它 registry。
- blob 改写回源经 Worker 转发，manifest/token 走 Worker；Worker Free 计划每次请求子请求上限（50）对单次 pull 足够。

## Star History

<a href="https://www.star-history.com/?repos=AinzRimuru%2FDockerProxyCF&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/chart?repos=AinzRimuru/DockerProxyCF&type=date&theme=dark&legend=top-left&sealed_token=-n8FUNYgqNuGOOTrdA9LM_YwIXKzFDZJWurWAG8A00n_cd-u-rpOkAmKJziw0X4llEuPYWwjCfuIgac2ZF0gCDPLk3an5mM3ybDcSZD2RJl2VuBUFrlapmAs5DXuW9RFa6r954vsYJ6jt5WcwOs-EL8hJQi8L23g9h-pgrttRe0mOr0cmLe2CNvJiYY6" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/chart?repos=AinzRimuru/DockerProxyCF&type=date&legend=top-left&sealed_token=-n8FUNYgqNuGOOTrdA9LM_YwIXKzFDZJWurWAG8A00n_cd-u-rpOkAmKJziw0X4llEuPYWwjCfuIgac2ZF0gCDPLk3an5mM3ybDcSZD2RJl2VuBUFrlapmAs5DXuW9RFa6r954vsYJ6jt5WcwOs-EL8hJQi8L23g9h-pgrttRe0mOr0cmLe2CNvJiYY6" />
   <img alt="Star History Chart" src="https://api.star-history.com/chart?repos=AinzRimuru/DockerProxyCF&type=date&legend=top-left&sealed_token=-n8FUNYgqNuGOOTrdA9LM_YwIXKzFDZJWurWAG8A00n_cd-u-rpOkAmKJziw0X4llEuPYWwjCfuIgac2ZF0gCDPLk3an5mM3ybDcSZD2RJl2VuBUFrlapmAs5DXuW9RFa6r954vsYJ6jt5WcwOs-EL8hJQi8L23g9h-pgrttRe0mOr0cmLe2CNvJiYY6" />
 </picture>
</a>

## 鸣谢

[LINUX DO - 新的理想型社区](https://linux.do)
