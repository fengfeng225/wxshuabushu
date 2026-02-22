# MiMotion Manager

小米运动（Zepp Life）步数管理系统。Docker 自部署，Web 管理后台，支持多账号批量刷步、定时执行、消息推送。

核心刷步引擎基于 [TonyJiangWJ/mimotion](https://github.com/TonyJiangWJ/mimotion)。

## 功能特性

- **多账号管理** - 添加/编辑/删除/启停账号，支持账号过期自动停用
- **智能步数曲线** - 基于日期 + 用户名的确定性种子，每天生成固定目标步数；5 种曲线模型（linear / ease-in / ease-out / smoothstep / slow-flat-fast）模拟真实运动轨迹
- **定时执行** - Cron 表达式配置，随机延迟分散请求，避免集中触发
- **账号注册** - 内置 Zepp 账号注册流程，含验证码获取与微信、支付宝绑定
- **Token 缓存** - 三级降级（app_token > login_token > access_token），AES 加密存储，减少登录请求
- **消息推送** - 支持 PushPlus / 企业微信 / Telegram
- **执行日志** - 完整记录每次执行的账号、步数、状态、输出，支持筛选和分页
- **Web 管理后台** - Bento Grid 风格 UI，响应式布局，Jinja2 服务端渲染

## 快速开始

### 1. 准备配置

```bash
cp .env.example .env
```

编辑 `.env`，至少修改以下项：

```env
APP_SECRET=your-random-secret-string
ADMIN_USER=admin
ADMIN_PASS=your-admin-password
VIEW_PASSWORD_KEY=your-view-key
```

### 2. Docker 部署（推荐）

```bash
docker compose up -d --build
```

访问 `http://localhost:9091` 进入管理后台。

### 3. 本地开发

```bash
pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

## 环境变量

| 变量                  | 必填 | 说明                             | 默认值                    |
| --------------------- | ---- | -------------------------------- | ------------------------- |
| `APP_SECRET`        | 是   | 应用密钥，用于 Session 加密      | -                         |
| `ADMIN_USER`        | 是   | 管理后台用户名                   | `admin`                 |
| `ADMIN_PASS`        | 是   | 管理后台密码                     | `admin`                 |
| `VIEW_PASSWORD_KEY` | 是   | 查看账号密码时的验证密钥         | -                         |
| `AES_KEY`           | 否   | 16 字节密钥，用于 Token 加密存储 | -                         |
| `DATA_DIR`          | 否   | 数据存储目录                     | `/data`                 |
| `MIMOTION_PATH`     | 否   | 刷步引擎脚本路径                 | `/app/mimotion/main.py` |
| `RANDOM_DELAY_MAX`  | 否   | Cron 模式下随机延迟最大分钟数    | `58`                    |

## 架构概览

```
mimotion-manager/
├── app/                    # FastAPI Web 应用
│   ├── main.py             # 路由、中间件、认证
│   ├── db.py               # SQLite 数据层（accounts / settings / runs）
│   ├── run_once.py         # 批量调度：账号遍历、延迟分散、子进程启动
│   ├── crypto.py           # Fernet 加密（基于 APP_SECRET 派生）
│   ├── step_api.py         # 第三方步数 API 客户端
│   ├── templates/          # Jinja2 模板
│   └── static/             # 静态资源
├── mimotion/               # 刷步引擎（独立子进程）
│   ├── main.py             # MiMotionRunner：登录、Token 管理、步数提交
│   └── util/
│       ├── zepp_helper.py  # Zepp/华米 API 封装（自动重试）
│       ├── aes_help.py     # AES-128-CBC 加解密
│       └── push_util.py    # 消息推送
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

### 子进程通信

`app/run_once.py` 通过 `subprocess.run` 启动 `mimotion/main.py`：

- **输入**: `CONFIG` 环境变量（JSON）传递账号配置，`TOKEN_DATA` 传递缓存 Token
- **输出**: stdout 中 `MM_RESULT|` 前缀行返回执行结果，`MM_TOKEN|` 前缀行返回更新后的 Token

### 数据库

SQLite，3 张表：

- `accounts` - 账号及加密密码/Token
- `settings` - 全局配置（单行，id=1）
- `runs` - 执行记录

迁移通过 `db.py` 中的 `_ensure_column` 启动时自动补列。

## 手动触发

```bash
# 本地
python run_once.py

# Docker 容器内（cron 模式）
docker compose exec -T mimotion env RUN_TRIGGER=cron python /app/run_once.py
```

## 技术栈

Python 3.11 / FastAPI / Uvicorn / SQLite / Jinja2 / Fernet + AES-128-CBC / Docker

## 致谢

- [TonyJiangWJ/mimotion](https://github.com/TonyJiangWJ/mimotion) - 核心刷步引擎
