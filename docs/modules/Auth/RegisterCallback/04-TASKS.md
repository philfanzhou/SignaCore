# 回调注册 — 任务清单 (TASKS)

> 本功能已实现完成，无待办任务。以下为代码评审清单。

```json
[
  {
    "id": "TASK-01",
    "status": "implemented",
    "depends_on": [],
    "action": "RegisterCallback gRPC 方法实现",
    "files": ["backend/Service/AuthServiceImpl.cs"],
    "acceptance": "有效请求注册成功；无效请求返回错误"
  },
  {
    "id": "TASK-02",
    "status": "to_review",
    "depends_on": [],
    "action": "RegisterCallback 未验证 CallbackUrl 格式（未调用 CallbackUrlValidator）",
    "files": ["backend/Service/AuthServiceImpl.cs:L183"],
    "acceptance": "确认是否应在 RegisterCallback 中验证 CallbackUrl 格式"
  }
]
```
