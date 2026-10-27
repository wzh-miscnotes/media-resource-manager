# 媒体资源库（media-resource-manager）

媒体资源库是一个**本地自托管的媒体资源管理服务**：负责资源的统一存储（资源池）、合集管理、回收站、按用户隔离的共享、上传与目录导入、本地封面生成。

它不绑定任何特定内容来源——你可以通过浏览器上传、目录导入，或对接你自己的获取工具（通过 ingest 接口）把媒体放进资源库。资源库只关心"如何存、如何去重、如何回收、如何授权共享"，不关心"内容从哪来"。

## 功能特性

- **媒体库**：按用户隔离的资源合集，支持封面、字幕、文章入口。
- **回收站**：删除引用后物理文件仍保留，可整条还原，防止误删。
- **共享**：生成共享令牌，接收方凭令牌可取流；支持资源级共享与隔离。
- **上传**：浏览器直传文件进资源池。
- **目录导入**：扫描本地目录，按内容哈希去重后批量入库。
- **本地封面**：缩略图本地缓存，无需外部图床。

## 关键概念

- **rid（资源主键）**：`r` + 内容 / 来源哈希前 15 位。本地文件推荐用内容哈希派生，去重强度最高。
- **body_key8（本体键前 8 位）**：区分同一资源的不同版本（如不同画质），决定落盘子目录。
- **资源池**：`downloads/resources/<rid>/<body_key8>/`，所有生产者的统一落盘位置。
- **回收站**：引用计数归零的资源进入回收站，物理保留，可恢复或清理。
- **共享隔离**：每个共享令牌绑定 owner + locked 状态；owner 删除自身引用即锁定令牌，不可重置开启。
- **ingest 接口**：`POST /api/ingest`。生产者只需把文件 staging 到临时区并调用该接口，资源库负责去重入池——耦合最低，也便于对接外部获取工具。

## 目录结构

```
media-resource-manager/
├── app.py                     # 后端服务（FastAPI）
├── index.html                 # 前端单页界面
├── config.py                  # 配置加载
├── config.example.json        # 配置样例（复制为 config.json 后填写）
├── requirements.txt           # Python 依赖
├── docs/
│   ├── 资源池与回收站设计-对外精简版.md  # 架构设计（当前权威版：去重/回收站/共享失效）
│   ├── 资源池与回收站设计.md    # v1 历史基准（已停止更新）
│   └── 字幕OCR方案.md          # 硬字幕 OCR 接入方案
└── downloads/                 # 运行时数据目录（gitignore，含 resources/、_collections/、.thumbnail_cache/ 等）
```

## 安装与运行

1. 安装依赖：
   ```bash
   pip install -r requirements.txt
   ```
2. 准备配置：复制 `config.example.json` 为 `config.json`，按需填写（见下文配置说明）。
3. 启动服务（界面与 API 同域托管，推荐）：
   ```bash
   python run_server.py
   ```
   `run_server.py` 会同时托管前端 `index.html` 与后端 API，默认监听 `0.0.0.0:5006`（端口见 `config.json`）。  
   若只想单独运行后端（不含界面），可用 `uvicorn app:app --host 0.0.0.0 --port 5006`，前端则需另起静态服务。
4. 浏览器访问服务地址（如 `http://localhost:5006`）即可使用。

> 注意：运行时会在 `downloads_dir`（默认项目内 `downloads/`）生成资源池、合集、缩略图缓存等，已被 `.gitignore` 排除，不会进入版本库。

## 配置说明（config.json）

| 字段                    | 说明                                                                          | 默认                    |
| --------------------- | --------------------------------------------------------------------------- | --------------------- |
| `host`                | 服务监听地址                                                                      | `127.0.0.1`           |
| `port`                | 服务端口                                                                        | `5006`                |
| `ffmpeg`              | ffmpeg 可执行路径（留空则走系统 PATH / imageio-ffmpeg）                                  | 空                     |
| `bin_dir`             | 额外二进制目录                                                                     | 空                     |
| `downloads_dir`       | 运行时数据根目录（资源池 / 合集 / 缓存）                                                     | 空（默认项目内 `downloads/`） |
| `thumbnail_cache_dir` | 缩略图缓存目录                                                                     | 空                     |
| `llm_*`               | 文章生成所需的 LLM 接口（`base_url` / `api_key` / `model` / `enabled`），详见 `config.py` | 本地 LM Studio 默认值      |

## 验证

1. 上传一个视频 → 进入资源池 `downloads/resources/<rid>/<body_key8>/`。
2. 媒体库可见该条目；删除引用 → 引用计数归零 → 回收站可见，物理文件保留。
3. 回收站还原 → 条目完整恢复（封面 / 字幕 / 文章入口齐全）。
4. 生成共享令牌 → 接收方凭令牌取流；owner 删除自身引用 → 令牌锁定。
5. 目录导入一个本地文件夹 → 按哈希去重入库。

## 部署

- 仓库已提供 `Dockerfile`（基于 `python:3.11-slim`，内置 ffmpeg 用于字幕 OCR，依赖走清华镜像），构建即用：


  ```bash
  docker build -t media-resource-manager:latest .
  docker run -d --name rm_app --network host -v "$PWD:/app" media-resource-manager:latest
  ```
  容器内由 `run_server.py` 托管前端与 API；端口由 `config.json` 的 `port` 控制（如与其它服务冲突，改为 `5007` 等即可）。
- 也可不用容器：`pip install -r requirements.txt` 后 `python run_server.py`。
- 多用户通过 `X-Session-Id` 请求头隔离；如需统一身份认证，可对接你自己的网关（注入该头即可）。

## 身份模式：网关 / 独立（auth_mode）

RM 本身不绑定任何账号体系——它把「用户」等同于**请求里解析出的身份字符串**，所有数据都按这个字符串分桶（`collections.json` 的键、`users/<hash>/` 目录、共享令牌的 owner）。`auth_mode` 决定这个字符串从哪来：

| auth_mode    | 身份来源                                            | RM 是否存密码 | 适用场景                  |
| ------------ | ----------------------------------------------- | -------- | --------------------- |
| `gateway`    | 只采信可信代理（`TRUSTED_PROXY_NETS`）注入的 `X-User-Email` | 否        | 部署在统一网关后，用户在网关侧管理     |
| `standalone` | RM 自带账号体系：登录后的会话 cookie                         | 是        | 完全独立部署，自带 admin 与用户管理 |
| `auto`（默认）   | 可信 email → `X-Session-Id` → 匿名                  | 否        | 兼容历史部署，也是两形态间的过渡桥     |

### 独立部署（standalone）

1. 配置：`config.json` 设 `"auth_mode": "standalone"`（或用环境变量 `RM_AUTH_MODE`）。
2. **首次启动自动引导 admin**：优先用环境变量 `RM_ADMIN_PASSWORD`；未设则生成随机密码并**打印到启动日志**。
3. 浏览器打开服务地址 → 弹出登录框，用 admin 登录（身份串 `admin@local`）。
4. admin 可在顶部「👥 用户管理」里新增 / 重置 / 删除用户。

```bash
docker run -d --name rm_app --network host \
  -e RM_AUTH_MODE=standalone \
  -e RM_ADMIN_PASSWORD=你的强密码 \
  -v "$PWD:/app" media-resource-manager:latest
```

> - 若密码是随机生成的，登录后请立即改掉（`POST /api/admin/password`）。
> - `RM_SECRET` 未设时每次启动重新生成签名密钥，**重启会让所有人登出**；生产环境建议固定该值。
> - 账号与口令哈希落在 `downloads/users/.admin.json` / `.accounts.json`（已 gitignore），**不会**写入 `config.json`。

### 网关部署（gateway）

`config.json` 设 `"auth_mode": "gateway"`，并把网关出口 IP 纳入 `TRUSTED_PROXY_NETS`（默认 `127.0.0.1`、`::1`、`172.19.0.0/16`，可用环境变量 `TRUSTED_PROXY_NETS` 覆盖）。用户在网关侧新增，网关注入 `X-User-Email: <用户名>@local` 即可——RM 不存密码、不引导 admin，也不采信客户端自报的 `X-Session-Id`。

### 两种模式互切与历史数据

- **可自由互切**：改 `auth_mode` 后重启即可，**不需要迁移数据**——数据只按身份字符串键存，不记录用了哪种模式。
- **无损切换的唯一前提**：独立模式账号一律归一化为 `<用户名>@local`（系统自动补后缀）。这样身份串与网关时代完全一致，`user_hash` 与合集键才能对上；否则会出现「库是空的」——数据仍在磁盘，只是换了哈希够不着。
- **删除账号不会删除资源**：数据留在 `users/<hash>/` 桶里，用同名重建账号即可取回（孤儿桶同理）。

## 文档

- `docs/资源池与回收站设计-对外精简版.md`：架构设计（当前权威版）——两层去重 key、入池路由、双层回收站、共享失效模型。
- `docs/资源池与回收站设计.md`：v1 历史基准，保留供追溯演进。
- `docs/字幕OCR方案.md`：硬字幕 OCR（olmOCR）接入方案。

## 使用与合规

- 本项目是**纯自托管的媒体资源库**，只负责存储、合集、回收站、共享与封面处理，**不内置任何内容下载、抓取或解密能力**；资源需由你通过上传、目录导入或自有工具（ingest 接口）放入。
- 仓库**不包含任何平台账号、Cookie、令牌或密钥**；运行时配置（`config.json`）与用户数据（`downloads/`、`users/`）均通过 `.gitignore` 排除。
- 内容版权与平台协议由**使用者自行负责**：请仅保存你有权保存的内容，遵守所在地区法律与内容来源方的用户协议，勿用于传播侵权内容或规避平台的技术措施。
- 第三方平台名称仅出现在代码注释或文件名解析等描述性场景，不表示任何隶属、授权或背书关系（参见 Apache-2.0 §6）。
- 本项目按 **AS IS** 提供，不附带任何明示或暗示担保（参见 Apache-2.0 §7）。

## License

![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)

本项目以 **Apache License 2.0** 开源，详见 [LICENSE](LICENSE)。

- 你可以使用、修改、分发本项目，包括用于商业用途，需保留版权与许可证声明。
- Apache-2.0 包含明确的专利授权条款与专利报复终止条款，对下游使用者与贡献者更友好。
- 若你基于本项目二次开发并分发，请提供 NOTICE（如有）并保留原始许可证文件。
