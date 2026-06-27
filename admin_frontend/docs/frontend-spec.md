# Identity Admin 前端 Spec

## 技术栈

| 项目 | 技术 |
|------|------|
| 框架 | Vue 3 + TypeScript |
| UI 库 | Element Plus |
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
│   ├── style.css                        # 全局样式
│   └── services/
│       └── adminApi.ts                  # API 客户端服务
├── public/
│   └── favicon.svg                      # 图标
└── package.json
```

> **架构说明**：Identity Admin 采用单组件架构，所有页面、对话框和交互逻辑都内联在 `App.vue` 中，无路由、无状态管理库、无独立组件文件。

---

## 页面布局

### 整体结构

```
┌──────────────────────────────────────────────────────────┐
│  侧边栏（可收起）                                         │
│  ┌─────────────────┐                                      │
│  │ QZ (Logo)      │                                      │
│  ├─────────────────┤                                      │
│  │ 用户管理       │ ← 激活状态                          │
│  │ 应用注册       │                                      │
│  │ 回调管理       │                                      │
│  │ 令牌管理       │                                      │
│  ├─────────────────┤                                      │
│  │ 管理员信息     │                                      │
│  └─────────────────┘                                      │
├──────────────────────────────────────────────────────────┤
│  顶部栏：导航菜单 + 刷新 + 用户名 + 退出                   │
├──────────────────────────────────────────────────────────┤
│  统计栏：用户总数 | 应用总数 | 已启用应用                 │
├──────────────────────────────────────────────────────────┤
│  主内容区（根据 activeTab 切换）                         │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 用户管理：用户表格 + 筛选 + 分页                    │  │
│  └────────────────────────────────────────────────────┘  │
│  或                                                       │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 应用注册：应用表格 + 操作                           │  │
│  └────────────────────────────────────────────────────┘  │
│  或                                                       │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 回调管理：配置表单 + 应用选择                       │  │
│  └────────────────────────────────────────────────────┘  │
│  或                                                       │
│  ┌────────────────────────────────────────────────────┐  │
│  │ 令牌管理：吊销刷新令牌                             │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

---

## 功能模块详细说明

### 1. 认证与登录

| 功能 | 说明 |
|------|------|
| 登录页 | 用户名 + 密码 + 7天免登录 |
| Session 恢复 | 页面加载时自动验证 Cookie 会话状态 |
| 登录状态保持 | Cookie 认证，支持持久会话 |
| 401 处理 | 会话过期时自动重置状态并返回登录页 |
| 白名单警告 | 后端未配置 AdminUsernames 时显示安全警告 |

**认证流程**：
1. 页面加载时调用 `/api/admin/session/me` 检查会话
2. 未登录时显示登录表单
3. 登录成功后设置 Cookie，加载用户和应用数据
4. 会话过期时自动清理并返回登录页

### 2. 用户管理

| 功能 | 说明 |
|------|------|
| 用户列表 | 分页展示（每页20条），支持按用户名/手机号搜索 |
| 创建密码账户 | 用户名 + 密码 + 备注 |
| 创建手机账户 | 手机号 + 备注 |
| 用户状态切换 | 启用/禁用用户账户 |
| 更新备注 | 修改用户备注信息 |

**用户列表列**：
- 用户名（显示头像和名称）
- 手机号
- 状态（已启用/已禁用）
- 备注
- 创建时间
- 操作

### 3. 应用注册

| 功能 | 说明 |
|------|------|
| 应用列表 | 展示所有 OAuth 应用 |
| 创建应用 | 应用名称 + 回调地址（可选）+ TTL |
| 重置密钥 | 重新生成 AppSecret（仅显示一次） |
| 删除应用 | 删除应用及其所有配置 |
| 配置回调 | 跳转回调管理页面 |

**应用列表列**：
- 应用名称（显示图标和名称）
- 应用 ID
- 回调地址
- 状态
- 回调过期时间
- 操作

### 4. 回调管理

| 功能 | 说明 |
|------|------|
| 选择应用 | 从下拉框选择要配置的应用 |
| 设置回调地址 | 修改回调 URL |
| TTL 设置 | 设置回调过期时间（秒） |
| 永不过期 | 开关控制回调是否过期 |
| 应用状态 | 启用/禁用应用 |

### 5. 令牌管理

| 功能 | 说明 |
|------|------|
| 吊销刷新令牌 | 输入刷新令牌并立即吊销 |
| 安全警告 | 显示操作后果提示 |

---

## API 调用汇总

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
| `/api/admin/tokens/revoke` | POST | 吊销刷新令牌 |

---

## 核心类型定义

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
  adminUsernamesConfigured: boolean
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

## 对话框清单

| 对话框 | 触发方式 | 功能 |
|--------|---------|------|
| 创建密码账户 | 用户管理点击"添加密码账户" | 输入用户名、密码、备注 |
| 创建手机账户 | 用户管理点击"添加手机账户" | 输入手机号、备注 |
| 创建应用 | 应用注册点击"添加应用" | 应用名称、回调地址、TTL |
| 密钥显示 | 创建/重置密钥后 | 显示 appSecret（仅一次） |
| 更新备注 | 用户表格点击"备注" | 弹出输入框修改备注 |

---

## 设计规范

- **UI 框架**：Element Plus + 自定义 CSS
- **布局**：侧边栏 + 顶部栏 + 主内容区
- **统计栏**：用户总数、应用总数、已启用应用
- **分页**：统一每页 20 条
- **认证**：基于 Cookie 会话，Axios 配置 `withCredentials: true`
- **错误处理**：Axios 错误统一提取 `response.data.message`，使用 ElMessage 提示
- **确认操作**：危险操作使用 ElMessageBox.confirm 二次确认
- **侧边栏**：支持收起和展开，状态保存在 localStorage
- **密钥安全**：AppSecret 仅在创建/重置时显示一次，不可再次获取
