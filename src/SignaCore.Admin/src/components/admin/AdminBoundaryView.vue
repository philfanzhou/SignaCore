<template>
  <section class="console-view">
    <div class="console-page-heading">
      <div>
        <p class="console-eyebrow">CAPABILITY BOUNDARY</p>
        <h1>能力边界</h1>
        <p>
          把后端真实支持的操作和规划中的能力分开，避免把设计稿误当成接口承诺。
        </p>
      </div>
    </div>
    <div class="boundary-grid">
      <article class="console-panel">
        <span class="boundary-kicker supported">当前可用</span>
        <h2>已接入真实 API</h2>
        <ul>
          <li>管理员会话登录、续期检查与退出</li>
          <li>账户分页查询、创建、备注/昵称更新、启停和登录历史</li>
          <li>应用注册、回调、TTL、身份源策略与受众模式</li>
          <li>短信/LDAP/微信准入及换票信任管理</li>
          <li>审计日志、原始 refresh token 撤销</li>
          <li>运行配置和数据库引导配置</li>
        </ul>
      </article>
      <article class="console-panel">
        <span class="boundary-kicker proposed">建议功能</span>
        <h2>当前后端不支持</h2>
        <ul>
          <li>RBAC、角色/权限 CRUD 和委派管理员</li>
          <li>API Scope、Identity Resource 管理</li>
          <li>应用服务端搜索、排序、分页和导出</li>
          <li>refresh token 列表、批量撤销、恢复</li>
          <li>应用删除恢复、批量启停和批量删除</li>
        </ul>
      </article>
    </div>
    <article class="console-panel implementation-note">
      <div class="panel-heading">
        <div>
          <p class="console-eyebrow">IMPLEMENTATION RULE</p>
          <h2>前端实现原则</h2>
        </div>
      </div>
      <div class="rule-list">
        <div>
          <b>01</b>
          <p>没有对应接口的按钮只显示边界说明，不伪造成功反馈。</p>
        </div>
        <div>
          <b>02</b>
          <p>
            拆分的应用策略接口顺序提交，失败时提示可能存在部分生效并强制刷新。
          </p>
        </div>
        <div>
          <b>03</b>
          <p>
            所有 Secret 和数据库密码只进入受控输入，不写入浏览器本地持久化。
          </p>
        </div>
      </div>
    </article>
  </section>
</template>
