-- Mock 邮件服务器收件箱。仅供测试:任何投递到本 Worker 的邮件都会入库,可在线/API 查看。
CREATE TABLE IF NOT EXISTS messages (
  id          TEXT PRIMARY KEY,       -- 随机消息 ID
  to_addr     TEXT NOT NULL,          -- 收件地址(小写)
  from_addr   TEXT,                   -- 发件地址
  subject     TEXT,
  text_body   TEXT,
  html_body   TEXT,
  code        TEXT,                   -- 从主题/正文中抽取的一次性验证码(若有)
  received_at INTEGER NOT NULL,       -- Unix 毫秒
  raw_size    INTEGER
);

CREATE INDEX IF NOT EXISTS idx_messages_to ON messages (to_addr, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_received ON messages (received_at DESC);
