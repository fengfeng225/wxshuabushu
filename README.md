# Mimotion Manager

基于 Docker 自部署的小米运动（Zepp Life）步数管理系统，提供 Web 管理界面，支持多账号批量管理、定时自动执行、消息推送通知。

核心刷步引擎 `mimotion/` 借鉴自 [TonyJiangWJ/mimotion](https://github.com/TonyJiangWJ/mimotion)，在其基础上封装了完整的 Web 管理后台和 Docker 部署方案。

## 功能特性

- **多账号管理** - 支持批量添加、编辑、启用/停用账号，密码加密存储
- **自动刷步** - 通过 Zepp Life（华米）API 提交步数数据
- **定时执行** - 配合 cron 定时任务自动运行，支持随机延迟分散执行
- **步数配置** - 全局步数范围 + 账号级覆盖 + 固定步数，灵活配置
- **Token 缓存** - 多级 Token 缓存策略（app_token > login_token > access_token），减少登录频率
- **消息推送** - 支持 PushPlus（微信）、企业微信 WebHook、Telegram Bot
- **执行记录** - 完整的执行日志，含今日统计和时间线视图
- **安全设计** - 账号密码 Fernet 加密存储，Token AES 加密持久化，管理后台登录鉴权

## 技术栈

| 层级     | 技术                                  |
| -------- | ------------------------------------- |
| Web 框架 | FastAPI + Uvicorn                     |
| 模板引擎 | Jinja2（服务端渲染）                  |
| 数据库   | SQLite                                |
| 加密     | Fernet（密码） + AES-128-CBC（Token） |
| 部署     | Docker + Docker Compose               |
| 运行时   | Python 3.11                           |

## 快速开始

### 1. 克隆项目

```bash
git clone https://github.com/fengfeng225/wxshuabushu
cd mimotion-manager
```

### 2. 配置环境变量

```bash
cp .env.example .env
```

编辑 `.env` 文件，修改以下配置：

```env
APP_SECRET=your-secret-key        # 应用密钥，用于 Session 签名和密码加密
ADMIN_USER=admin                  # 管理后台用户名
ADMIN_PASS=your-admin-password    # 管理后台密码
VIEW_PASSWORD_KEY=your-view-key   # 查看账号密码的二次验证密钥
AES_KEY=                          # 16 字节 AES 密钥，用于 Token 持久化（留空则不缓存 Token）
```

### 3. 启动服务

```bash
docker compose up -d
```

服务启动后访问 `http://localhost:8000`，使用 `.env` 中配置的管理员账号登录。

### 4. 配置定时任务（可选）

在宿主机添加 cron 定时任务，定时触发刷步：

```bash
# 每天 6点、8点、10点...20点 各执行一次
0 6,8,10,12,14,16,18,20 * * * docker compose -f /path/to/docker-compose.yml exec -T mimotion env RUN_TRIGGER=cron python /app/run_once.py
```

多账号会在 `RANDOM_DELAY_MAX`（默认 58 分钟）范围内均匀分散执行，避免集中请求。

## 项目结构

```
mimotion-manager/
├── app/                    # Web 应用
│   ├── main.py             # FastAPI 主应用（路由、中间件）
│   ├── db.py               # SQLite 数据库操作层
│   ├── crypto.py           # Fernet 加密/解密
│   ├── step_api.py         # 第三方步数 API（来源：https://bs.yanwan.store/run4）
│   ├── run_once.py         # 批量执行调度逻辑
│   ├── static/             # 静态资源（CSS、图标）
│   └── templates/          # Jinja2 HTML 模板
├── mimotion/               # 核心刷步引擎
│   ├── main.py             # 刷步主逻辑（登录、Token 管理、提交步数）
│   └── util/
│       ├── aes_help.py     # AES-128-CBC 加解密
│       ├── zepp_helper.py  # Zepp/华米 API 交互
│       └── push_util.py    # 消息推送（PushPlus/企业微信/Telegram）
├── data/                   # 运行时数据（Docker 挂载卷）
│   ├── mimotion.db         # SQLite 数据库
│   └── encrypted_tokens.data  # 加密的 Token 缓存
├── run_once.py             # 顶层执行入口
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

## 执行架构

```
[cron 定时任务] 或 [Web 手动触发]
        |
        v
  run_once.py (入口)
        |
        v
  app/run_once.py (调度层)
    - 读取数据库中的账号和设置
    - 过滤过期账号，自动停用
    - 构建分散调度计划
    - 逐个账号以子进程执行
        |
        v
  mimotion/main.py (刷步引擎，子进程)
    - 多级 Token 缓存登录
    - 向 Zepp Life API 提交步数
    - 输出结果，推送通知
        |
        v
  app/run_once.py (结果收集)
    - 解析执行输出
    - 更新数据库执行记录
```

## 使用说明

### Web 管理界面

- **首页** - 账号列表，支持搜索、分页、启用/停用、测试刷步
- **新增账号** - 填写手机号和密码，支持设置固定步数或自定义步数范围
- **系统设置** - 配置全局步数范围、执行策略、推送渠道
- **执行记录** - 查看历史执行日志，含成功/失败统计

### 步数配置优先级

1. 账号固定步数（最高优先级）
2. 账号级步数范围覆盖
3. 全局步数范围（默认 18000-25000）

### 消息推送

在系统设置中配置推送渠道，执行完成后自动发送结果通知：

| 渠道     | 配置项              |
| -------- | ------------------- |
| PushPlus | Token               |
| 企业微信 | WebHook URL         |
| Telegram | Bot Token + Chat ID |

## 环境变量说明

| 变量                  | 必填 | 说明                                         |
| --------------------- | ---- | -------------------------------------------- |
| `APP_SECRET`        | 是   | 应用密钥，用于 Session 签名和 Fernet 加密    |
| `ADMIN_USER`        | 是   | 管理后台用户名                               |
| `ADMIN_PASS`        | 是   | 管理后台密码                                 |
| `VIEW_PASSWORD_KEY` | 是   | 查看账号密码的二次验证密钥                   |
| `AES_KEY`           | 否   | 16 字节密钥，用于 Token 持久化加密           |
| `DATA_DIR`          | 否   | 数据目录路径，默认 `/data`                 |
| `MIMOTION_PATH`     | 否   | 刷步引擎路径，默认 `/app/mimotion/main.py` |
| `RANDOM_DELAY_MAX`  | 否   | cron 模式最大随机延迟（分钟），默认 `58`   |

## 致谢

- [TonyJiangWJ/mimotion](https://github.com/TonyJiangWJ/mimotion) - 核心刷步引擎参考实现
- [bs.yanwan.store](https://bs.yanwan.store/run4/) - 第三方步数接口

## 免责声明

本项目仅供学习交流使用，请勿用于商业用途。使用本项目产生的任何后果由使用者自行承担。
