# 实体关系图

## 核心关系

```
┌─────────────┐       ┌────────────────────────┐
│   accounts   │1─────*│ password_credentials    │
│              │       │ (account_id → id)       │
│              │       └────────────────────────┘
│              │
│              │1─────*┌────────────────────────┐
│              │       │ user_logins             │
│              │       │ (account_id → id)       │
│              │       └────────────────────────┘
│              │
│              │1─────*┌────────────────────────┐
│              │       │ refresh_tokens          │
│              │       │ (account_id → id)       │
│              │       │ app_id ──┐              │
└─────────────┘       └──────────│──────────────┘
                                 │
┌──────────────────────┐         │
│  app_registrations   │1───────*┘
│  (app_id)            │   (逻辑引用，无 FK 约束)
└──────────────────────┘

┌──────────────────────┐
│  security_keys       │   (独立，无外键关系)
└──────────────────────┘

┌──────────────────────┐
│  otps                │   (独立，无外键关系)
└──────────────────────┘

┌──────────────────────┐
│  login_attempts      │   (独立，无外键关系)
└──────────────────────┘

┌──────────────────────┐
│  login_histories     │   (account_id 逻辑引用 accounts)
└──────────────────────┘

┌──────────────────────┐
│  audit_logs          │   (actor_id 逻辑引用 accounts)
└──────────────────────┘
```

## 关系说明

| 从表 | 到表 | 关系类型 | 外键字段 | 说明 |
|------|------|----------|----------|------|
| password_credentials | accounts | 多对一 | account_id | 一个账户可有多个用户名凭证 |
| user_logins | accounts | 多对一 | account_id | 一个账户可绑定多个外部登录 |
| refresh_tokens | accounts | 多对一 | account_id | 一个账户可有多个刷新令牌 |
| refresh_tokens | app_registrations | 多对一（逻辑） | app_id | 令牌关联到应用，无 FK 约束 |
| login_histories | accounts | 多对一（逻辑） | account_id | 登录失败时 account_id 可为 NULL |
| audit_logs | accounts | 多对一（逻辑） | actor_id | 操作者 ID，可为 NULL |
