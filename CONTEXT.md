# Identity and Access

Identity and Access 定义平台如何识别和认证账户。它不定义 Student、Teacher 或 Assistant 等业务身份。

## Language

**Account**:
可被认证并获得稳定标识的身份主体；业务上下文通过 Account ID 引用它。
_Avoid_: User、Student、Teacher、Assistant

**Credential**:
Account 用来证明身份的秘密或外部登录绑定。
_Avoid_: Profile、Role

**Token**:
认证成功后签发的有时效声明集合，用于向其他上下文证明 Account 身份。
_Avoid_: Session Data、Business Permission

**App Registration**:
获准与 Identity and Access 建立信任关系的业务应用身份。
_Avoid_: User Account、Portal

**Authentication**:
确认请求方控制某个 Account 的过程。
_Avoid_: Authorization、Staff Membership
