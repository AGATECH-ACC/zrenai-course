# Verification record

## Implemented scope

Local persisted administrator and agent application, including referral relationships, course catalog, orders, annual personal performance, automatic promotion, commission ledger, payout recording, refund clawbacks, Token balances, role-scoped CSV exports and audit events. The original explanation page and export were updated to the subsequently confirmed terms.

## Authoritative checks

- `python3 -m unittest discover -s tests -v`: **15 tests passed**.
- `node --check static/app.js`: passed.
- Python compilation of `store.py`, `server.py`, `backup.py`: passed.
- Live database: SQLite integrity and foreign-key checks passed. Seven products seeded; no test users, agents, orders, commissions, payouts or Token entries in the live database.
- Online SQLite backup completed and verified using the QA database.
- Browser QA in a separate database: administrator setup, agent creation, draft order, policy configuration, full payment entry, commission review, settlement recording and refund.
- Observed RM 6,980 sales order → RM 1,396 direct commission. Settled commission followed by full refund → RM -1,396 recoverable balance. Gift of 680 Token reversed to zero.
- Browser QA of alternate configuration: architect-only delivery and manual Token release; operator order produced 300 Token after explicit release.
- Desktop and 390px mobile checked, no document horizontal overflow; browser console showed no application errors.
- User-facing live instance responds at http://127.0.0.1:8787 with first-administrator setup.

## Current operational state

Local application is installed and running. The user creates their own administrator credentials. Annual performance resets while partner status remains; refund eligibility is recomputed across qualifying years. Direct commissions are 20% / 30%, promotion applies from the next order, and channel commissions are capped at 30%, excluding delivery.

Real payment posting is intentionally disabled until the user selects delivery scope and Token timing. Those business choices were explicitly left unconfirmed. Upstream multi-level allocation is supported but unconfigured because no complete allocation schedule has been confirmed. No bank payment, external model recharge, cloud deployment, or public access has been performed.

`dashboard-preview.jpg` contains synthetic QA data, not production results.

## 2026-10-12 · 个人推广工作台

- 20 项自动测试通过，覆盖原账务流程以及推广归属、意向去重、转换幂等、代理间资料隔离、管理员专属操作、无效与停用推广码、人数校验、同源校验、定制报价权限、演示账号的重复启动保留。
- 浏览器使用 demo.subadmin 验证：课程推荐页提交虚构购买意向 → 本人客户列表收到 → 保存跟进 → 转成 RM 3,980 待收款订单。没有执行收款或生成佣金，原 25 笔佣金测试订单未改动。
- 新增账号 demo.subadmin（演示密码与其他演示账号一致），保留两条尚待处理的购买意向，以及浏览器验证生成的一笔订单。
- 推广中心复制推荐文案提示成功；控制台无 error/warn。界面截图：subadmin-preview.png。
- 正式库未注入示例数据。推荐链接仍限本机访问，没有公开部署或发送 WhatsApp。
