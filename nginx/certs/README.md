# SSL 证书目录

部署前请将您的 SSL 证书文件放入此目录：

- `cert.pem` — SSL 证书（fullchain）
- `key.pem` — 私钥

**这些文件不应提交到 Git 仓库！** 已在 `.gitignore` 中排除。

## 使用 Let's Encrypt 申请免费证书

```bash
certbot certonly --standalone -d YOUR_DOMAIN
cp /etc/letsencrypt/live/YOUR_DOMAIN/fullchain.pem nginx/certs/cert.pem
cp /etc/letsencrypt/live/YOUR_DOMAIN/privkey.pem nginx/certs/key.pem
```

## 自签名证书（仅开发测试）

```bash
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout nginx/certs/key.pem \
  -out nginx/certs/cert.pem \
  -subj "/CN=localhost"
```
