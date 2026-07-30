# Identity Admin Frontend

Identity 服务的 Web 管理控制台，基于 Vue 3 + TypeScript + Vite + Element Plus 构建。

采用单组件架构，所有页面和交互逻辑内联在 `App.vue` 中，无路由、无状态管理库。

## 功能

- 用户管理（创建密码/手机账户、启用/禁用、更新备注）
- 应用注册管理（创建应用、重置密钥、删除应用、配置回调）
- 令牌管理（吊销刷新令牌）

## 开发

```bash
npm install
npm run dev
```

开发服务器默认地址：`http://localhost:5173`，API 代理至 `http://localhost:5002`。

## 构建

```bash
npm run build
```

## 前端规范

详见 [frontend-spec.md](docs/frontend-spec.md)。
