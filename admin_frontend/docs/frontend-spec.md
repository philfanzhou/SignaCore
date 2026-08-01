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
│   ├── App.vue                          # 组装根（会话三分支 + 组件组装 + 生命周期接线）
│   ├── main.ts                          # 入口文件（按顺序 import 9 个样式文件）
│   ├── env.d.ts                         # window.__APP_TITLE__ 类型声明
│   ├── components/                      # 展示组件（零 props，直接从 composable 取状态）
│   │   ├── AuthView.vue                 # 会话检查页 + 登录页
│   │   ├── AppSidebar.vue               # 侧边栏（brand/nav/底部署名 + 移动遮罩 + nav 指示器）
│   │   ├── AppTopbar.vue                # 顶部栏（汉堡/面包屑/刷新/环境标签/时钟/登出）
│   │   ├── StatBar.vue                  # 统计栏（4 卡片 + 数字滚动动效）
│   │   ├── UsersTab.vue                 # 用户管理 tab
│   │   ├── AppsTab.vue                  # 应用注册 tab
│   │   ├── CallbacksTab.vue             # 回调管理 tab
│   │   ├── TokensTab.vue                # 令牌管理 tab
│   │   ├── UserDrawer.vue               # 用户 drawer
│   │   ├── AppDrawer.vue                # 应用 drawer
│   │   └── modals/                      # 6 个模态框（创建密码/手机账户、注册应用、密钥显示、编辑备注、删除应用确认）
│   ├── composables/                     # 模块级单例状态与逻辑（域 → useSession → sessionHooks 单向依赖）
│   │   ├── sessionHooks.ts              # 注册表：resetAllDomains / loadAllDomains / refreshAll
│   │   ├── useSession.ts                # 会话域 + 401 管线 + appTitle
│   │   ├── useUsers.ts                  # 用户域（含用户 drawer、备注 modal、开户 modal×2）
│   │   ├── useApps.ts                   # 应用域（含应用 drawer、回调表单、密钥/删除 modal 组）
│   │   ├── useTokens.ts                 # 令牌吊销
│   │   ├── useViewNav.ts                # activeTab / sidebarOpen / viewLeaving / navigateTo
│   │   ├── useClock.ts                  # 顶栏时钟
│   │   └── useOverlay.ts                # Esc 层级 + body 滚动锁定（initialized 守卫）
│   ├── services/
│   │   ├── adminApi.ts                  # API 客户端（类型 + AdminApiClient）
│   │   └── apiClient.ts                 # 单一 axios 实例（adminClient）
│   ├── utils/
│   │   ├── icons.ts                     # 线性 SVG 图标字典（I）
│   │   └── format.ts                    # formatDate / formatTtl / getInitials / normalizeTtlValue
│   └── styles/                          # 全局样式（无 scoped，main.ts 按级联顺序引入）
│       ├── tokens.css                   # Design Token（:root 变量）
│       ├── base.css                     # reset / 滚动条 / body
│       ├── auth.css                     # 登录/会话检查页
│       ├── layout.css                   # app-shell / sidebar / topbar
│       ├── components.css               # 卡片/按钮/输入/徽章/chip/表格/switch/统计卡/分页/空态/告警
│       ├── overlays.css                 # drawer / modal
│       ├── toast.css                    # ElMessage 全局覆写（必须在 element-plus css 之后）
│       ├── utilities.css                # spinner / section-gap
│       └── responsive.css               # 响应式断点（最后加载）
├── public/
│   └── favicon.svg                      # 图标
└── package.json
```

> **架构说明**：组件 + composable 单例架构（2026-07-22 由 1714 行单组件拆分，行为零变化）。无路由、无状态管理库、无路径 alias；跨组件共享状态经 composable 模块级单例（`useXxx()` 返回同一状态），依赖方向固定为"域 composable → useSession → sessionHooks"，域在模块顶层 `registerSessionHooks({ reset, load })` 自注册，useSession 的 `resetAdminState` 与登录/会话恢复路径经注册表回到各域，避免循环依赖。drawer 状态并入所属域 composable（用户 drawer→useUsers，应用 drawer+回调表单→useApps）；模板 ref 与效果代码同组件绑定（nav 指示器→AppSidebar，数字滚动→StatBar）。

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
│  │ 身份卡图标 + 服务名 + 副标题 │                                │
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
│  统计栏（4 卡片网格）：用户总数 / 应用总数（OAuth 应用）/ 已启用应用 / 已停用应用   │
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
| 显示密钥 | 创建/重置密钥后 | 标题固定"保存你的 App Secret"，副标题含 App ID（mono）；密钥展示框 + 复制按钮（复制成功后按钮短暂显示"已复制"）+ "我已保存"勾选（勾选才能完成） |
| 编辑备注 | 用户 drawer 中"编辑"按钮 | 备注 textarea |
| 删除应用确认 | 应用 drawer 中"删除应用"按钮 | 输入 App ID 确认（输入正确才能永久删除） |

### 品牌与标题来源（2026-07-21 去业务化 + 标题参数化修正）

Identity 是面向任意系统提供鉴权能力的通用服务，管理控制台**不得**出现具体业务方品牌（如"若愚学习平台"）。所有标题（浏览器 tab、侧边栏 brand、登录页副标题）**统一来自运行时注入的 `APP_TITLE`**，禁止在前端硬编码，以便同一镜像适配不同项目部署：

```
start.sh 传参 -e APP_TITLE="${CONTAINER_NAME}"
  → 后端 Program.cs 读取 APP_TITLE 配置（缺省 "QuantumZhou.Identity"）
  → 运行时替换 index.html 的 <title>__APP_TITLE__</title> 占位符（浏览器 tab 标题）
  → 注入 <script>window.__APP_TITLE__ = '...'</script> 到 <head>
  → 前端 appTitle = window.__APP_TITLE__ || 'QuantumZhou.Identity'（前端兜底值）
```

- `index.html` 必须保留 `<title>__APP_TITLE__</title>` 占位符，**禁止**替换为硬编码文案（否则后端运行时注入失效）
- 侧边栏 brand：渐变方块内为线性身份卡 SVG 图标（非汉字"若"），主文案为 `{{ appTitle }}`，副标题固定为 `管理控制台`
- 登录页 / 会话检查页：`auth-logo` 同样使用身份卡 SVG 图标，副标题为 `{{ appTitle }} 管理控制台`
- `window.__APP_TITLE__` 的 TS 声明位于 `src/env.d.ts`

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
| 用户列表 | 分页展示（每页20条），支持按用户名/手机号搜索；触发搜索时重置到第 1 页再查询 |
| 状态筛选 | chip 切换：全部 / 已启用 / 已禁用（前端筛选当前页数据，不影响 API 参数） |
| 创建密码账户 | 用户名 + 密码 + 备注（模态框） |
| 创建手机账户 | 手机号 + 备注（模态框） |
| 用户状态切换 | 表格内 switch 开关 + drawer 底部按钮，调用同一 API；切换前弹确认框，取消或接口失败时 switch 视觉状态回滚 |
| 更新备注 | drawer 中"编辑"按钮触发模态框；保存后列表与 drawer 同步为最新数据 |
| 用户 drawer | 点击用户行打开，展示基本信息 + 编辑备注 + 状态切换；列表刷新后若该用户仍在当前结果集内，drawer 内数据同步最新 |

**用户表格列**（按样稿）：
- 用户（头像 + 昵称/用户名）
- 手机号
- 类型（密码账户 / 手机账户，由后端返回的 `hasPassword` 判定：`true` = 密码账户（indigo 徽章），`false` = 手机账户（blue 徽章）。**禁止**再用 `username` 是否为空推导——后端对手机账户的 `username` 字段回退返回手机号，判空恒为真，曾导致手机账户全部误显示为"密码账户"）
- 备注
- 创建时间
- 状态（switch 开关，stopPropagation 防止触发 drawer）

### 3. 应用注册

| 功能 | 说明 |
|------|------|
| 应用列表 | 展示所有 OAuth 应用 |
| 创建应用 | 应用名称 + 回调地址（可选）+ TTL+单位下拉 |
| 应用 drawer | 点击应用行打开，集成回调配置 + 重置密钥 + 删除应用；"保存配置"成功后关闭 drawer 并刷新列表 |
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
interface PagedResponse<T> {
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
  hasPassword: boolean   // 是否存在密码凭据：true=密码账户，false=手机账户
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
- **toast**：右上角，深色背景，spring 入场（基于 ElMessage 全局样式覆盖实现，复用 toast-in 动效）
- **浮层**：Esc 可关闭 modal 与 drawer（ElMessageBox 确认框打开时除外）；浮层打开期间锁定 body 滚动

### 动效清单

1. **数字滚动**：统计卡数字 ease-out 1s 滚动到位（用 requestAnimationFrame 实现）
2. **nav 指示器滑动**：spring 曲线 0.34s 跟随激活项（登录/会话恢复后也会初始化定位）
3. **页面切换**：200ms 模糊+位移过渡（opacity + filter blur + translateY）
4. **卡片 hover 上浮**：22ms ease
5. **抽屉入场**：30ms ease 位移+透明度（拆分 visible/open 双状态驱动进出场过渡）
6. **模态框入场**：26ms spring 缩放+透明度（v-if 挂载触发 keyframes：modal-pop / overlay-fade）
7. **toast 入场**：30ms spring 位移
8. **switch 切换**：22ms spring 位移

### 图标系统

采用样稿的线性 SVG 图标（stroke 1.6，stroke-linecap round，stroke-linejoin round），覆盖：grid / users / app / shield / file / search / upload / back / x / copy / check / clock / refresh / eye / alert / zap / book / image / chev / menu / logout / key / plus / db / doc / warnTri。

---

## 修复记录（2026-07-21 对照样稿全面检查）

> 检查基准：`prototype/admin-console-redesign.html` + 本规范。每项按「问题 / 位置 / 预期 / 修复方案 / 状态」记录。
> 红线复核：本轮修复 `adminApi.ts` 与后端零改动；不引入新依赖、不拆分组件；范围裁定（系统切换器/Overview/审计页/登录历史 tab/强制下线）维持不变。

### P0 — 功能阻断

#### F1: 侧边栏遮罩常驻渲染，登录后整个页面无法点击

- **问题**：`.overlay`（sidebar 遮罩）在已登录主界面中常驻渲染，基础样式 `opacity: 0; position: fixed; inset: 0; z-index: 90`。`opacity:0` 的元素仍接收指针事件，不可见遮罩覆盖主内容区与顶栏，吞掉全部点击。
- **位置**：`App.vue` 主界面模板（sidebar overlay）+ `style.css` `.overlay`
- **预期**（依样稿）：遮罩仅在需要时可见且可点击；桌面端不需要 sidebar 遮罩（样稿 ≤900px 才用汉堡菜单）。
- **修复**：`.overlay` 基础态加 `pointer-events: none`，`.overlay.open` 恢复 `pointer-events: auto`；sidebar 遮罩加 `sidebar-overlay` 类，仅 ≤900px 显示。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F2: 全部 6 个 modal 不可见且被遮罩吞点击

- **问题**：①所有 modal 元素从未添加 `.open` 类，停留在 `opacity:0; transform:scale(.96)` 初始态，永久不可见；②`.modal-wrap` 内 overlay 继承 `.overlay` 的 `z-index:90`，高于无定位的 `.modal`，即使可见也会遮住 modal 并拦截其内部全部点击。影响：创建密码/手机账户、注册应用、密钥显示、编辑备注、删除应用确认 6 个弹窗全部不可用。
- **位置**：`App.vue` 各 modal 模板 + `style.css` `.modal` / `.modal-wrap .overlay`
- **预期**（依样稿）：modal `scale(.96)→1` spring 入场、overlay 渐显、modal 内容可交互。
- **修复**：`.modal` 基础态改为最终视觉态并加 `animation: modal-pop .26s var(--spring)`（v-if 挂载即播放入场，保证任何情况下可见）；`.modal` 加 `position:relative; z-index:1`；`.modal-wrap .overlay` 覆写 `z-index:0; pointer-events:auto; animation: overlay-fade .22s forwards`。移除不再使用的 `.modal.open` 规则。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F3: drawer 入场/退场动效丢失

- **问题**：drawer 的 `v-if` 与 `.open` 类绑定同一状态，元素挂载即最终态，无滑入过渡；关闭时立即卸载，无滑出过渡。
- **位置**：`App.vue` 用户/应用 drawer 模板与 openUserDrawer/closeUserDrawer 等函数
- **预期**（依样稿）：drawer 从右侧 36px 位移+淡入滑入，关闭时反向滑出（样稿 double-rAF 加 open 类、300ms 后移除）。
- **修复**：拆分 `visible`（控制挂载）与 `open`（控制 .open 类）双状态：打开时先挂载、double-rAF 后置 open；关闭时先清 open、300ms 过渡结束后卸载。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

### P1 — 功能缺陷

#### F4: 表格状态 switch 取消/失败后视觉状态不回滚

- **问题**：switch 的 `:checked` 单向绑定，用户点击后 DOM 立即翻转；在确认框点"取消"或接口失败时无重渲染，switch 停留在错误视觉状态，与数据不一致。
- **位置**：`App.vue` 用户表格 switch + `handleToggleUserStatus`
- **预期**：取消或失败时 switch 回到真实状态。
- **修复**：`@change` 传入 `$event`，取消/失败分支重置 `input.checked = user.isActive`。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F5: 编辑备注保存后用户 drawer 显示旧值

- **问题**：`loadUsers()` 整体替换 `users` 数组，`userDrawerUser` 仍引用旧对象，drawer 内备注、状态徽章等不更新（列表刷新 drawer 不同步）。
- **位置**：`App.vue` `loadUsers` / `saveEditRemark`
- **预期**（依任务清单）：保存后 drawer 与列表同步更新。
- **修复**：`loadUsers` 成功后按 `userId` 重新查找并同步 `userDrawerUser`；同理 `loadApps` 同步 `appDrawerApp`。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F6: 应用 drawer 保存配置后不关闭且数据陈旧

- **问题**：drawer 内"保存配置"成功后 drawer 保持打开，`appDrawerApp` 为旧对象（状态徽章等不更新）；样稿行为是保存即关闭 drawer。
- **位置**：`App.vue` `handleSaveCallback` + 应用 drawer 底部按钮
- **预期**（依样稿）：保存成功 → 关闭 drawer + toast + 列表刷新。
- **修复**：`handleSaveCallback` 返回是否成功；drawer 保存按钮经包装函数在成功后调用 `closeAppDrawer()`（回调管理 Tab 复用同一保存函数，不受影响）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F7: 搜索不重置页码

- **问题**：在第 N 页（N>1）输入关键词搜索时仍按当前页查询，匹配结果在前面页时当前页显示空列表，表现为"搜索无结果"。
- **位置**：`App.vue` 用户搜索输入框/搜索按钮 → `loadUsers`
- **预期**：触发搜索时回到第 1 页查询。
- **修复**：新增 `handleSearch()`：`page = 1` 后调 `loadUsers()`，搜索输入回车与搜索按钮均改接 `handleSearch`。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F8: TTL 小时换算用 floor，与规范"向上取整"不符

- **问题**：`fillCallbackForm` 与 `formatTtl` 用 `Math.floor(remaining/3600)`。刚设置 2 小时（7200s）后几秒即显示/回填为 1 小时；规范明确"显示为小时（向上取整，最少 1）"。
- **位置**：`App.vue` `fillCallbackForm` / `formatTtl`
- **预期**（依本规范 TTL 换算规则）：小时向上取整，最少 1。
- **修复**：两处均改 `Math.max(1, Math.ceil(remainingSec / 3600))`。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F9: TTL 输入为空/非法时提交 NaN

- **问题**：`v-model.number` 下清空输入得到 `''`，`'' * 3600 = 0`；非法输入得 `NaN`，序列化为 `null` 提交，后端校验失败或产生 0 秒 TTL。
- **位置**：`App.vue` `handleCreateApp` / `handleSaveCallback`
- **预期**：TTL 至少为 1（对应样稿 `Math.max(1, parseInt(...||'1'))` 的钳制）。
- **修复**：提交换算前统一经 `normalizeTtlValue`（`Math.max(1, Math.floor(n))`，非法值回退 1）；API 契约与换算规则不变。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F10: 登录/会话恢复后 nav 指示器不显示

- **问题**：`updateNavIndicator` 仅在 `onMounted`（此时侧边栏尚未渲染）与 Tab 切换时执行；登录或会话恢复后指示器保持 `opacity: 0`，首次点击 Tab 前激活项无高亮胶囊。
- **位置**：`App.vue` `onMounted` / `updateNavIndicator`
- **预期**（依样稿）：激活 nav 项始终有高亮胶囊+左侧高亮条。
- **修复**：`watch(isAuthenticated)`，变为 true 后 `nextTick` 更新指示器。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F11: 密钥 modal 缺所属 App ID，标题与样稿不符

- **问题**：密钥 modal 标题为"应用创建成功/密钥重置成功"，副标题未说明密钥属于哪个应用；样稿标题固定"保存你的 App Secret"，副标题含 `应用 <mono>{appId}</mono> · 此密钥仅显示这一次`。
- **位置**：`App.vue` 密钥 modal 模板 + `handleCreateApp` / `handleResetSecret`
- **预期**（依样稿）：标题"保存你的 App Secret"，副标题含 App ID。
- **修复**：新增 `latestSecretAppId`，创建/重置时记录；modal 标题固定，副标题渲染 App ID（mono）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F12: 手机账户状态切换确认文案用户名为空

- **问题**：确认框文案使用 `user.username`，手机账户该字段为空，显示 `确定要禁用用户 "" 吗？`。
- **位置**：`App.vue` `handleToggleUserStatus`
- **预期**：回退到 displayName / userId。
- **修复**：名称取 `user.username || user.displayName || user.userId`。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### F13: 删除应用后回调管理表单残留已删应用

- **问题**：被删应用若正选中在回调管理 Tab，`callbackForm.appId` 残留，下拉无匹配项但表单字段仍显示旧值。
- **位置**：`App.vue` `handleDeleteApp`
- **预期**：删除成功后清空回调表单选中态。
- **修复**：删除成功时若 `callbackForm.appId === 被删 appId`，重置回调表单。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

### P2 — 细节偏差

#### D1: toast 未按样稿实现（右上角深色 spring）

- **问题**：`style.css` 中 `#toast-root`/`.toast` 是死代码（无渲染入口）；实际用 ElMessage 默认样式（白卡、顶部居中），与样稿"右上角、深色背景、spring 入场"不符。
- **位置**：`style.css` toast 区块 + ElMessage 全局样式
- **预期**（依样稿）：右上角深色 toast，spring 入场。
- **修复**：移除死代码，保留 `toast-in` keyframes；全局覆盖 `.el-message` 为右上角深色样式（right:18px、ink-1 底、ink-line 边、spring 入场动画、成功/失败/警告图标色与样稿一致）。
- **复审修正（2026-07-21 code review）**：首轮覆盖被 EP 2.13.7 的 `.el-message.is-center{left:50%;transform:translate(-50%)}`（特异性 0,2,0）击败，定位与退场动效未生效。修正：以同等特异性追加 `.el-message.is-center{left:auto;transform:none}`、`.el-message-fade-enter-from.is-center` / `.el-message-fade-leave-to.is-center{transform:translateX(24px)}`（style.css 后加载，同特异性后者胜）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D2: 侧边栏底部 admin 角色文案与样稿不符

- **问题**：角色文案为"超级管理员"，样稿为"引导超级管理员"。（头像经核对本即显示 2 字符，与样稿 "AD" 一致，无需处理。）
- **位置**：`App.vue` sidebar-foot
- **修复**：角色文案改为"引导超级管理员"。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D3: 会话检查页与登录页不一致

- **问题**：会话检查页 logo 为 "QZ"（登录页为"若"）；`.auth-logo` 缺 flex 居中，字符不居中。
- **位置**：`App.vue` checkingSession 模板 + `style.css` `.auth-logo`
- **修复**：会话检查页头部与登录页统一（若 + 欢迎回来 + QuantumZhou.Identity 管理控制台）；`.auth-logo` 加 flex 居中。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D4: 用户表格"类型"徽章多了状态点

- **问题**：样稿类型徽章（密码账户/手机账户）无状态点，当前实现含 `.dot`。
- **位置**：`App.vue` 用户表格类型列
- **修复**：移除类型徽章内的 dot 元素。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D5: 分页器总数文案与样稿不符

- **问题**：当前"共 N 条"，样稿"共 N 个账户"。
- **位置**：`App.vue` 用户分页器
- **修复**：改为"共 {{ userTotal }} 个账户"。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D6: 密钥复制按钮无"已复制"反馈

- **问题**：样稿复制成功后按钮短暂变为"已复制"（check 图标），当前仅 ElMessage 提示。
- **位置**：`App.vue` 密钥 modal 复制按钮 + `copySecret`
- **修复**：新增 `secretCopied` 状态，复制成功后按钮文本/图标切换 1.5s。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D7: 回调管理页头部重复的"保存配置"按钮

- **问题**：page-actions 幽灵按钮与表单底部主按钮功能重复，易造成困惑。
- **位置**：`App.vue` 回调管理 page-head
- **修复**：移除页头按钮，仅保留表单底部"保存回调配置"主按钮。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D8: 缺 Escape 关闭 modal/drawer

- **问题**：样稿按 Esc 关闭 modal 与 drawer，当前实现未绑定。
- **位置**：`App.vue` 生命周期
- **修复**：注册 keydown 监听，按层级关闭（modal 优先于 drawer；ElMessageBox 打开时不处理）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D9: 浮层打开期间未锁定 body 滚动

- **问题**：样稿打开 drawer 时 `body.overflow = hidden`，当前未锁定。
- **位置**：`App.vue` 浮层状态
- **修复**：watch 任一 drawer/modal 打开状态，切换 body overflow。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D10: 移动端侧边栏被自身遮罩盖住

- **问题**：≤900px 时 sidebar `z-index:40` 低于遮罩 `z-index:90`，打开侧边栏会被遮罩覆盖且无法点击。
- **位置**：`style.css` 响应式区块
- **修复**：≤900px 时 `.sidebar { z-index: 92 }`（高于遮罩 90、低于 drawer 95）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### D11: 时间格式月/日不补零

- **问题**：`formatDate` 输出 `2025/9/2 10:24`，样稿风格为补零（`2025-09-02 10:24`）。
- **位置**：`App.vue` `formatDate`
- **修复**：月/日/时/分统一 padStart(2,'0')，分隔符统一为 `-`（输出 `2025-09-02 10:24`）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

---

## 修复记录（2026-07-21 品牌去业务化 + 账户类型判据修正）

> 背景：①Identity 定位是面向任意系统的通用鉴权服务，管理控制台残留业务方品牌"若 / 若愚学习平台"；②用户列表/详情的账户类型用 `username` 判空推导，但后端 `AdminUserListItemResponse.Username` 对手机账户回退返回手机号（`username ?? phone`），导致存量手机账户全部误显示为"密码账户"。本轮后端 DTO 新增 `HasPassword` 字段（存在密码凭据 = 密码账户），前端统一改用该字段。

#### G1: 品牌绑定具体业务（"若 / 若愚学习平台"），且标题未走 APP_TITLE 参数化

- **问题**：侧边栏 brand（`brand-mark` 汉字"若" + `brand-text`"若愚学习平台"）、登录页/会话检查页 `auth-logo`（汉字"若"）硬编码业务方品牌；Identity 作为通用鉴权服务不应绑定任何具体业务。且既有需求是所有标题来自 `start.sh` 的 `APP_TITLE` 参数（后端 `Program.cs` 已实现运行时注入 `__APP_TITLE__` 占位符 + `window.__APP_TITLE__` 全局变量），但前端从未消费该变量，`index.html` 的 `<title>__APP_TITLE__</title>` 占位符还一度被误改为硬编码文案（会导致后端替换失效）。
- **位置**：`App.vue` 会话检查页/登录页头部、侧边栏 brand；`index.html` title；新增 `src/env.d.ts`
- **预期**：品牌仅体现部署方通过 `APP_TITLE` 注入的标题，图标为中性的身份卡线性 SVG；浏览器 tab 标题由后端替换占位符生成，页面内标题与 tab 同源。
- **修复**：`index.html` 恢复 `<title>__APP_TITLE__</title>` 占位符；新增 `env.d.ts` 声明 `window.__APP_TITLE__`；`App.vue` 以 `appTitle = window.__APP_TITLE__ || 'QuantumZhou.Identity'` 读取，brand 主文案与登录页/会话检查页副标题统一改用 `appTitle`；`brand-mark` / `auth-logo` 内汉字"若"替换为身份卡 SVG 图标（沿用图标系统 stroke 1.6 规范）。
- **状态**：✅ 已修复（2026-07-21，`npm run build` 通过，vue-tsc 零类型错误）

#### G2: 手机账户类型误显示为"密码账户"

- **问题**：用户表格"类型"徽章与用户 drawer"账户类型"均按 `user.username` 是否非空推导。后端投影 `name = username ?? phone`，手机账户的 `username` 返回手机号（恒非空），所有手机账户显示为"密码账户"。
- **位置**：`App.vue` 用户表格类型列、用户 drawer KV 网格；后端 `AdminController.GetUsers` / `UserQueryService.ProjectUsersAsync` 投影；`AdminUserListItemResponse`（Host 与 Domain 两份同构定义）
- **预期**：账户类型以后端权威字段为准——存在密码凭据（password_credentials）= 密码账户，否则 = 手机账户。
- **修复**：`AdminUserListItemResponse` 新增 `HasPassword`（两份定义同步），投影以 `credentials.ContainsKey(account.Id)` 填充；前端 `AdminUser` 类型加 `hasPassword`，列表徽章文案/配色与 drawer 账户类型统一改用 `hasPassword`。
- **状态**：✅ 已修复（2026-07-21，后端单元测试 264 通过含新增 HasPassword 判据用例，`npm run build` 通过，vue-tsc 零类型错误）

---

## 重构记录（2026-07-22 大文件拆分 + 死代码清理）

> 背景：`App.vue`（1714 行单组件）与 `style.css`（1622 行）是可维护性主要瓶颈。本轮按"行为零变化"铁律完成结构重组：状态/方法/模板/样式逐块搬运，不改变任何交互与视觉。

#### R1: App.vue 单组件拆分（1714 行 → 约 80 行组装根 + 16 组件 + 8 composable + 2 utils）

- **拆分方案**：composable 模块级单例承载状态与逻辑（useSession / useUsers / useApps / useTokens / useViewNav / useClock / useOverlay / sessionHooks 注册表），组件零 props 直接从 composable 解构；依赖方向"域 → useSession → sessionHooks"单向无环。
- **关键裁定**：drawer 状态并入域 composable（避免 loadXxx 同步 drawer 与 drawer 操作回写列表的循环依赖）；回调域并入 useApps（callbackForm 被回调 tab 与应用 drawer 双向共用）；nav 指示器归 AppSidebar、数字滚动归 StatBar（模板 ref 与效果同组件绑定）。
- **等价简化（行为不变）**：navigateTo 不再显式 `nextTick(updateNavIndicator)`（watch(activeTab) 必然触发同一更新）；计数 watch 仅在 StatBar 挂载期间激活。
- **状态**：✅ 已完成（2026-07-22，`npm run build` 通过，vue-tsc 零类型错误）

#### R2: style.css 拆分（1622 行 → styles/ 9 文件）

- **拆分方案**：tokens / base / auth / layout / components / overlays / toast / utilities / responsive，main.ts 按级联顺序 import；全部样式无 scoped，顺序与原单文件一致（已用逐字节 diff 验证拼接后与原文件完全一致）。toast.css（`.el-message.is-center` 覆写）保持在 element-plus css 之后，responsive.css 最后。
- **状态**：✅ 已完成（2026-07-22）

#### R3: 死代码清理

- **前端逻辑**：`lastRefreshTime` / `updateRefreshTime`（只写不读）及其在 loadUsers/loadApps 中的调用；`adminApi.testConnection`（无调用方）。
- **CSS 死类**（grep 确认零模板引用后删除）：`.checkbox-wrap`、`.badge.amber`、`.badge.red`、`.trend-up`、`.trend-down`、`.form-group` 半选择器（保留 `.field` 半选择器）。
- **依赖移除**：`pinia`、`vue-router`、`@element-plus/icons-vue`（已安装但从未在 src 中引用；锁文件已更新）。
- **状态**：✅ 已完成（2026-07-22，`npm run build` 通过）

---

## 文档约定

- 本文件是 Identity Admin 前端的唯一权威规范
- 任何视觉/交互变更必须先更新本文件再改代码
- API 契约变更不在本文件范围（属后端 docs/modules/）
- 行为变化后必须回写本文件
