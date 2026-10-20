# 云端部署

## 生产环境

- 网站：https://zrenai.aiedu.academy/
- 管理员及代理登录：https://zrenai.aiedu.academy/admin
- Vercel team / project：`agatechteam` / `zrenai-course`
- GitHub：`AGATECH-ACC/zrenai-course`，生产分支 `main`
- Supabase：`crzeiwqcsthxwcajnnai`，私有业务 schema `zrenai_course`
- 运行时：Flask、Python 3.12；依赖固定于根目录 `requirements.txt`。

原有本地及独立演示启动方式保持可用。演示账号、SQLite 数据文件和本地登录会话不发布至生产环境。

## 环境变量

在 Vercel production 配置以下变量，不写入仓库：

| 变量 | 用途 |
| --- | --- |
| `DATABASE_URL` | Supabase transaction pooler 6543 的受限 `zrenai_course_app` 登录连接 |
| `PUBLIC_ORIGIN` | `https://zrenai.aiedu.academy` |
| `SUPABASE_URL` | Supabase 项目 URL |
| `SUPABASE_PUBLISHABLE_KEY` | Supabase 公开 publishable key |

数据库密码仅作为服务器端敏感环境变量保存。代码强制 `verify-full`，使用随代码附带的 Supabase 公共 CA 证书，不关闭证书校验。公开 key 不能访问业务 schema；业务表均启用 RLS，仅受限服务器数据库角色可读写，不能读取 Auth 用户表或支付系统 schema。

Supabase Auth Site URL 配置为 `https://zrenai.aiedu.academy/admin`。管理员和代理需先由应用授权；任意 Supabase 注册用户不会自动获得后台权限。生产 cookie 为 `__Host-zr_session`，带 Secure、HttpOnly、SameSite=Strict。写操作检查精确 Origin 和 CSRF；登录、注册和意向提交限制持久保存在数据库。

## 首次迁移（已完成，不要重复导入）

1. 通过受控迁移创建受限登录角色，密码在仓库外生成。
2. 应用 `agent-system/sql/cloud-schema.sql`，不授予运行角色建表权限。
3. 在目标表为空时运行 `scripts/import_cloud.py`，从正式 SQLite 复制用户授权、课程、规则和业务记录。脚本拒绝 demo 数据库，并排除所有登录会话。
4. 导入后按现有最大 ID 校准 policies/audit identity sequence。

运行时只读写现有表，不自动创建管理员、不执行 DDL。生产数据库与 `zrenai_payment` 独立，后者不属于这份部署迁移。

## 验证与发布

```sh
python3 -m unittest discover -s agent-system/tests -v
node --check agent-system/static/app.js
.venv/bin/python scripts/test_web_runtime.py
vercel deploy --dry --json --project zrenai-course --scope agatechteam
vercel deploy --prod --skip-domain --yes --project zrenai-course --scope agatechteam
```

先在生成的部署 URL 检查首页、静态资源、`/admin` 和 `/api/session`。未登录 `/api/dashboard` 应返回 401，跨站写入应返回 403，环境文件和数据库文件应返回 404。验证后使用 `vercel promote <部署 URL> --scope agatechteam` 更新域名。

`scripts/test_cloud.py` 仅在预先创建的 `zrenai_course_test_deploy` schema 运行真实 Postgres 业务回归；会清空该测试 schema 中的 fixture，绝不指向正式表。完成后可删除测试 schema。认证回归使用模拟认证服务，不代表已用真人密码完成生产登录。

## 持久化及回滚

Vercel 文件系统不保存订单或会话。所有正式业务修改写入 Supabase Postgres；事务锁防止并发支付、退款、晋升重复记账。金额使用整数分，数据库聚合结果在 JSON 输出前转换为整数。

代码回滚使用 Vercel 已验证部署，回滚不还原或删除数据库记录。执行任何未来 schema 变更前，先确认 Supabase 备份覆盖与恢复方案；本地 SQLite 备份脚本仅适用于本地环境。

正式运营前仍需由业务方确认收款、Token 发放和交付费口径；部署不会自动批准这些规则。Supabase 邮件发送限额及自定义 SMTP 配置会影响新增用户激活邮件，现有用户登录不依赖邮件发送。当前 Auth advisor 提示未启用泄露密码检查，可按 [Supabase 密码安全说明](https://supabase.com/docs/guides/auth/password-security#password-strength-and-leaked-password-protection) 配置。
