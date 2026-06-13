# 网关用户查询 — 任务清单 (TASKS)

```json
[
  {
    "id": "TASK-01",
    "status": "implemented",
    "depends_on": [],
    "action": "网关用户搜索和批量查询",
    "files": ["backend/Host/Controllers/GatewayController.cs"],
    "acceptance": "有效凭证可搜索和批量查询用户"
  },
  {
    "id": "TASK-02",
    "status": "to_review",
    "depends_on": [],
    "action": "ProjectUsersAsync 先 ToList 再内存分页，大数据量下性能问题",
    "files": ["backend/Host/Controllers/GatewayController.cs:L129-134"],
    "acceptance": "确认是否需要改为数据库层面分页"
  }
]
```
