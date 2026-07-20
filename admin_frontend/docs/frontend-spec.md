# Identity Admin 前端 Spec

## 技术栈

| 项目 | 技术 |
|------|------|
| 框架 | Vue 3 + TypeScript |
| UI 库 | Element Plus（仅用 ElMessage / ElMessageBox） |
| HTTP 客户端 | Axios |
| 构建工具 | Vite |
| 入口 | `src/main.ts` |

---

## 项目结构

```
admin_frontend/
├── src/
│   ├── App.vue                          # 主应用（单组件架构）
│   ├── main.ts                          # 入口文件
│   ├── style.css                        # 全局样式 + Design Token
│   └── services/
│       └── adminApi.ts                  # API 客户端服务
├── public/
│   └── favicon.svg                      # 图标
└── package.json
```

> **架构说明**：Identity Admin 采用单组件架构，所有页面、抽屉、对话框和交互逻辑都内联在 `App.vue` 中，无路由、无状态管理库、无独立组件文件。本次重设计仅改展示层，不拆分组件。

---

## 重设计来源与范围（2026-07-20）

### 样稿
- 文件：`prototype/admin-console-redesign.html`
- 样稿含两个系统（identity / doclib）切换、Overview、Audit 等页面。

### 范围裁定（基于"业务逻辑零改动"与"数据必须真实"两条铁律）

| 样稿点位 | 处置 | 原因 |
|---------|------|------|
| 系统切换器（identity/doclib） | **不实现** | DocLibrary 是独立服务，不属于本前端工程范围 |
| Identity 概览页（Overview） | **不实现** | 登录趋势/审计 feed/今日登录数无对应 admin API，做静态皮违反"数据必须真实" |
| Identity 审计日志页 | **不实现** | 后端 `audit_logs` 表存在但无 admin 读取 API |
| 用户管理 / 应用注册 / 回调管理 / 令牌管理 | **重设计** | 沿用现有 4 个 Tab，按样稿设计语言重包装 |
| 用户 drawer 中的"登录历史"tab | **不实现** | 无 admin API 查询用户登录历史 |
| 用户 drawer 中的"强制下线"按钮 | **不实现** | 现有 `/api/admin/tokens/revoke` 接收 `refreshToken` 字符串，不接收 `userId`，无法做按用户吊销 |
| 应用 drawer 中的回调配置 | **实现** | 现有 `PUT /api/admin/apps/{appId}/callback` 完全支持，drawer 形态是展示层变更 |
| 应用 drawer 中的重置密钥 / 删除应用 | **实现** | 现有 API 支持 |
| 密钥显示模态框的"我已保存"勾选 | **实现** | 展示层交互形式变更，不影响 API |
| 删除应用二次确认输入 App ID | **实现** | 展示层交互形式变更，不影响 API |
| 数字滚动、SVG 描画、nav 指示器滑动、卡片 hover 上浮、抽屉/弹窗入场动效 | **实现** | 纯展示层 |

### 业务逻辑零改动自查清单

`git diff` 中**不应**出现以下变更：
- `adminApi.ts` 中任何端点 URL、请求参数、响应处理
- `App.vue` `<script setup>` 中任何 API 调用、状态管理逻辑、表单校验规则、错误处理流程
- 任何后端文件

允许的变更：模板结构、CSS 样式、icon 资源、展示层交互形式（drawer/modal 入场动效、chip 筛选 UI、TTL 单位下拉、密钥确认勾选、删除确认输入框）。

---

## 页面布局

### 整体结构

```
┌─────────────────────────────────────────────────────────────┐
│  侧边栏（深色渐变，固定 248px）                                │
│  ┌──────────────────────┐                                   │
│  │ 若愚 Logo + 副标题    │                                   │
│  ├──────────────────────┤                                   │
│  │ QuantumZhou.Identity │  ← 系统标签（仅展示，无切换器）    │
│  │ ▸ 用户管理            │  ← 激活态有左侧高亮条 + 背景胶囊   │
│  │   应用注册            │                                   │
│  │   回调管理            │                                   │
│  │   令牌管理            │                                   │
│  ├──────────────────────┤                                   │
│  │ admin 头像 + 角色     │                                   │
│  └──────────────────────┘                                   │
├─────────────────────────────────────────────────────────────┤
│  顶部栏（毛玻璃）：面包屑 + 内网环境标签 + 实时时钟 + 退出     │
├─────────────────────────────────────────────────────────────┤
│  统计栏（4 卡片网格）：用户总数 / 应用总数 / 已启用 / 已禁用   │
├─────────────────────────────────────────────────────────────┤
│  主内容区（根据 activeTab 切换，200ms 模糊过渡）              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │ 用户管理：搜索 + chip 筛选 + 表格 + 分页                │ │
│  │ 应用注册：表格 + AppSecret 提示条                       │ │
│  │ 回调管理：表单（应用选择 + URL + TTL + 开关）           │ │
│  │ 令牌管理：警告条 + textarea + 吊销按钮                  │ │
│  └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

### 抽屉（Drawer）

- **用户 drawer**：点击用户行触发。头部（头像 + 名称 + ID + 状态徽章 + 关闭）→ mini-tabs（仅"基本信息"）→ KV 网格（手机号/账户类型/备注[编辑]/创建时间）→ 底部按钮（关闭 + 启用/禁用账户）。
- **应用 drawer**：点击应用行触发。头部（应用图标 + 名称 + AppID + 状态徽章 + 关闭）→ 回调配置卡片（URL 输入 / TTL 数字+单位下拉 / 启用开关）→ 危险区（重置密钥 / 删除应用）→ 底部按钮（取消 + 保存配置）。

### 模态框（Modal）

| 模态框 | 触发 | 字段 |
|--------|------|------|
| 创建密码账户 | "添加密码账户"按钮 | 用户名 / 密码 / 备注 |
| 创建手机账户 | "添加手机账户"按钮 | 手机号 / 备注 |
| 注册应用 | "注册应用"按钮 | 应用名 / 回调地址（可选） / TTL+单位下拉 |
| 显示密钥 | 创建/重置密钥后 | 密钥展示框 + 复制按钮 + "我已保存"勾选（勾选才能完成） |
| 编辑备注 | 用户 drawer 中"编辑"按钮 | 备注 textarea |
| 删除应用确认 | 应用 drawer 中"删除应用"按钮 | 输入 App ID 确认（输入正确才能永久删除） |

---

## 功能模块详细说明

### 1. 认证与登录

| 功能 | 说明 |
|------|------|
| 登录页 | 用户名 + 密码 + 7天免登录（保留现有实现，按样稿设计语言重包装） |
| Session 恢复 | 页面加载时自动验证 Cookie 会话状态 |
| 登录状态保持 | Cookie 认证，支持持久会话 |
| 401 处理 | 会话过期时自动重置状态并返回登录页 |

**认证流程**（不变）：
1. 页面加载时调用 `/api/admin/session/me` 检查会话
2. 未登录时显示登录表单
3. 登录成功后设置 Cookie，加载用户和应用数据
4. 会话过期时自动清理并返回登录页

### 2. 用户管理

| 功能 | 说明 |
|------|------|
| 用户列表 | 分页展示（每页20条），支持按用户名/手机号搜索 |
| 状态筛选 | chip 切换：全部 / 已启用 / 已禁用（前端筛选当前页数据，不影响 API 参数） |
| 创建密码账户 | 用户名 + 密码 + 备注（模态框） |
| 创建手机账户 | 手机号 + 备注（模态框） |
| 用户状态切换 | 表格内 switch 开关 + drawer 底部按钮，调用同一 API |
| 更新备注 | drawer 中"编辑"按钮触发模态框 |
| 用户 drawer | 点击用户行打开，展示基本信息 + 编辑备注 + 状态切换 |

**用户表格列**（按样稿）：
- 用户（头像 + 昵称/用户名）
- 手机号
- 类型（密码账户 / 手机账户，由 `username` 是否为空推导）
- 备注
- 创建时间
- 状态（switch 开关，stopPropagation 防止触发 drawer）

### 3. 应用注册

| 功能 | 说明 |
|------|------|
| 应用列表 | 展示所有 OAuth 应用 |
| 创建应用 | 应用名称 + 回调地址（可选）+ TTL+单位下拉 |
| 应用 drawer | 点击应用行打开，集成回调配置 + 重置密钥 + 删除应用 |
| 重置密钥 | drawer 危险区按钮，重置后弹密钥模态框 |
| 删除应用 | drawer 危险区按钮，二次确认输入 App ID |
| AppSecret 安全提示 | 表格下方信息条 |

**应用表格列**（按样稿）：
- 应用（图标 + 名称）
- App ID（等宽字体）
- 回调地址（等宽字体，未配置灰色）
- 回调有效期（按 TTL 计算：≥24h 显示天，否则显示小时；永不过期显示"永不过期"）
- 状态（徽章）
- 进入 drawer 的箭头

### 4. 回调管理（独立 Tab，保留）

| 功能 | 说明 |
|------|------|
| 选择应用 | 下拉框选择 |
| 设置回调地址 | 输入框 |
| TTL 设置 | 数字 + 单位下拉（小时/天） + 永不过期开关 |
| 应用状态 | 启用/禁用开关 |
| 保存 | 调用 `PUT /api/admin/apps/{appId}/callback` |

**TTL 单位换算规则**（展示层，API 契约不变）：
- 用户输入：数字 + 单位（h 或 d）+ 永不过期开关
- 提交到 API 前的换算：
  - 永不过期 → `ttlSeconds = -1`
  - 单位为天 → `ttlSeconds = value × 86400`
  - 单位为小时 → `ttlSeconds = value × 3600`
- 回填表单时的反向换算（`fillCallbackForm`）：
  - `callbackExpiresAt` 为 null 且有 callbackUrl → 永不过期
  - 剩余秒数能被 86400 整除 → 显示为天
  - 否则 → 显示为小时（向上取整，最少 1）
- 应用表格"回调有效期"列展示规则（`formatTtl`）：
  - 无 callbackUrl → `-`
  - `callbackExpiresAt` 为 null → `永不过期`
  - 剩余秒数 ≥ 86400 且能整除 → `X 天`
  - 否则 → `X 小时`

### 5. 令牌管理

| 功能 | 说明 |
|------|------|
| 吊销刷新令牌 | textarea 输入 refresh token 字符串 + 吊销按钮 |
| 安全警告 | 顶部警告条 |

---

## API 调用汇总（不变）

### 会话管理

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/admin/session/login` | POST | 管理员登录 |
| `/api/admin/session/me` | GET | 获取当前会话信息 |
| `/api/admin/session/logout` | POST | 退出登录 |

### 用户管理

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/admin/users` | GET | 获取用户列表（支持分页和搜索） |
| `/api/admin/users` | POST | 创建密码账户 |
| `/api/admin/users/phone` | POST | 创建手机账户 |
| `/api/admin/users/{userId}/status` | PATCH | 切换用户状态 |
| `/api/admin/users/{userId}/remark` | PATCH | 更新用户备注 |

### 应用管理

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/admin/apps` | GET | 获取应用列表 |
| `/api/admin/apps` | POST | 创建应用（返回 appSecret） |
| `/api/admin/apps/{appId}` | DELETE | 删除应用 |
| `/api/admin/apps/{appId}/reset-secret` | POST | 重置应用密钥 |
| `/api/admin/apps/{appId}/callback` | PUT | 更新回调配置 |

### 令牌管理

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/admin/tokens/revoke` | POST | 吊销刷新令牌（接收 refreshToken 字符串） |

---

## 核心类型定义（不变）

```typescript
interface AdminPagedResponse<T> {
  items: T[]
  total: number
  page: number
  pageSize: number
}

interface AdminUser {
  userId: string
  username: string
  phone: string
  isActive: boolean
  remark: string
  nickname: string | null
  createdAt: number
  displayName: string
}

interface AdminApp {
  appId: string
  appName: string
  callbackUrl: string
  callbackExpiresAt: number | null
  isActive: boolean
  createdAt: number
}

interface AdminSession {
  accountId: string
  username: string
  isAuthenticated: boolean
}

interface AdminCreateUserRequest {
  username: string
  password: string
  displayName?: string
  remark?: string
  nickname?: string
}

interface AdminCreatePhoneUserRequest {
  phone: string
  displayName?: string
  remark?: string
  nickname?: string
}

interface AdminCreateAppRequest {
  appName: string
  callbackUrl?: string
  ttlSeconds: number
}

interface AdminUpdateCallbackRequest {
  callbackUrl?: string
  ttlSeconds: number
  isActive: boolean
}
```

---

## 设计规范（按样稿 prototype/admin-console-redesign.html）

### Design Token（CSS 变量）

```css
/* 主色 - Indigo */
--primary: #4F46E5;
--primary-hover: #4338CA;
--primary-soft: #EEF2FF;
--primary-line: #C7D2FE;

/* 侧边栏深色 */
--ink-0: #0D0F1E;
--ink-1: #141731;
--ink-2: #1D2142;
--ink-line: #262B52;
--ink-text: #E7E9F5;
--ink-text-2: #9BA1C4;
--ink-text-3: #5D6388;

/* 中性 */
--bg: #F5F6F8;
--surface: #FFFFFF;
--surface-2: #F8F9FC;
--border: #E5E7EF;
--border-2: #EEF0F6;
--text: #161927;
--text-2: #586076;
--text-3: #9AA0B6;

/* 语义色 */
--success: #10B981; --success-soft: #ECFDF5; --success-line: #A7F3D0;
--warning: #D97706; --warning-soft: #FFFBEB; --warning-line: #FDE68A;
--danger: #EF4444;  --danger-soft: #FEF2F2;  --danger-line: #FECACA;
--info: #0EA5E9;    --info-soft: #F0F9FF;    --info-line: #BAE6FD;

/* 圆角 */
--r-card: 12px;
--r-btn: 8px;
--r-input: 6px;

/* 阴影 */
--shadow-hover: 0 6px 16px -6px rgba(22,25,39,.12), 0 2px 4px -2px rgba(22,25,39,.06);
--shadow-float: 0 16px 40px -12px rgba(22,25,39,.18), 0 4px 10px -4px rgba(22,25,39,.08);

/* 动效曲线 */
--ease: cubic-bezier(.22,.61,.36,1);
--spring: cubic-bezier(.34,1.35,.44,1);

/* 等宽字体 */
--mono: ui-monospace,"SF Mono","Cascadia Code","JetBrains Mono",Consolas,monospace;
```

### 字体层级

| 用途 | 字号 | 字重 |
|------|------|------|
| 页面标题 | 23px | 650 |
| 卡片标题 | 14.5px | 600 |
| 模态框标题 | 16px | 650 |
| 抽屉标题 | 16.5px | 650 |
| 统计数字 | 29px | 680 |
| 正文 | 13.5px | 400 |
| 辅助文字 | 12.5px | 400 |
| 表头 | 11.5px | 600（letter-spacing .4px） |
| 等宽 | 12.5px | 400 |

### 间距与圆角

- 卡片 padding: 24px
- 抽屉宽度: 520px
- 按钮 height: 34px（小按钮 28px）
- 输入框 height: 34px
- 徽章 height: 23px
- chip height: 29px

### 组件模式

- **按钮**：主（primary indigo）/ 幽灵（白底灰边）/ 危险（白底红边）/ 小号
- **徽章**：灰/绿/琥珀/红/蓝/靛，圆角 20px，含状态点
- **chip 筛选**：圆角 16px，激活态 primary-soft 底色
- **switch 开关**：34×20，开启 success 色，spring 动效
- **卡片 hover**：translateY(-2px) + shadow-hover
- **表格行**：可点击行 hover surface-2 底色
- **抽屉**：右侧 520px 滑入，30px ease 入场
- **模态框**：scale(.96)→1 spring 入场
- **toast**：右上角，深色背景，spring 入场

### 动效清单

1. **数字滚动**：统计卡数字 ease-out 1s 滚动到位（用 requestAnimationFrame 实现）
2. **nav 指示器滑动**：spring 曲线 0.34s 跟随激活项
3. **页面切换**：200ms 模糊+位移过渡（opacity + filter blur + translateY）
4. **卡片 hover 上浮**：22ms ease
5. **抽屉入场**：30ms ease 位移+透明度
6. **模态框入场**：26ms spring 缩放+透明度
7. **toast 入场**：30ms spring 位移
8. **switch 切换**：22ms spring 位移

### 图标系统

采用样稿的线性 SVG 图标（stroke 1.6，stroke-linecap round，stroke-linejoin round），覆盖：grid / users / app / shield / file / search / upload / back / x / copy / check / clock / refresh / eye / alert / zap / book / image / chev / menu / logout / key / plus / db / doc / warnTri。

---

## 文档约定

- 本文件是 Identity Admin 前端的唯一权威规范
- 任何视觉/交互变更必须先更新本文件再改代码
- API 契约变更不在本文件范围（属后端 docs/modules/）
- 行为变化后必须回写本文件
