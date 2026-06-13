# 用户管理 — 任务清单 (TASKS)

> 本功能已实现完成，无待办任务。以下为代码评审清单。

```json
[
  {
    "id": "TASK-01",
    "status": "implemented",
    "depends_on": [],
    "action": "Admin Session 管理（登录/获取会话/登出）",
    "files": ["backend/Host/Controllers/AdminController.cs"],
    "acceptance": "管理员可登录、获取会话信息、登出"
  },
  {
    "id": "TASK-02",
    "status": "implemented",
    "depends_on": [],
    "action": "用户 CRUD 操作（创建/查询/修改备注/昵称/状态）",
    "files": ["backend/Host/Controllers/AdminController.cs"],
    "acceptance": "管理员可创建密码/手机用户、查询用户、修改用户信息"
  },
  {
    "id": "TASK-03",
    "status": "to_review",
    "depends_on": [],
    "action": "GetUsers 方法先 ToList 再内存分页，大数据量下性能问题",
    "files": ["backend/Host/Controllers/AdminController.cs:L155-159"],
    "acceptance": "确认是否需要改为数据库层面分页"
  }
]
```
