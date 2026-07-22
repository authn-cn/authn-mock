-- Mock 微信扫码登录的扫码会话(ticket)。扫码轮询天生需要跨请求/跨 isolate 的共享状态,
-- 故落库 D1。仅供测试:短时效,过期自净。
CREATE TABLE IF NOT EXISTS wechat_tickets (
  id         TEXT PRIMARY KEY,       -- 随机 ticket id(二维码里携带)
  status     TEXT NOT NULL,          -- PENDING / CONFIRMED / CANCELLED
  code       TEXT,                   -- 确认后签发的授权码(签名 JWT)
  appid      TEXT,                   -- 发起扫码的 appid
  scope      TEXT,                   -- 请求的 scope
  created_at INTEGER NOT NULL        -- 创建时间(Unix 毫秒)
);

CREATE INDEX IF NOT EXISTS idx_wechat_tickets_created ON wechat_tickets (created_at);
