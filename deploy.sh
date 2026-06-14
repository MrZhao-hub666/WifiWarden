#!/bin/bash
# WiFiWarden 一键部署脚本

set -e

echo "=========================================="
echo "WiFiWarden 部署脚本"
echo "=========================================="

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误: Docker 未安装${NC}"
    exit 1
fi

# 检查 Docker Compose (支持 docker-compose 和 docker compose 两种形式)
if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}错误: Docker Compose 未安装${NC}"
    exit 1
fi

# 确定使用的 docker compose 命令
if command -v docker-compose &> /dev/null; then
    DC_CMD="docker-compose"
else
    DC_CMD="docker compose"
fi

echo -e "${GREEN}Docker 检查通过${NC}"

# 创建必要的目录
mkdir -p nginx/certs mosquitto/config mosquitto/data mosquitto/log app/data app/templates

# ========== 新增：检查必要文件 ==========
echo ""
echo -e "${YELLOW}[1/6] 检查必要文件...${NC}"

# 检查 app 目录下的必要文件
REQUIRED_FILES=(
    "app/Dockerfile"
    "app/requirements.txt"
    "app/app.py"
    "app/state.py"
    "app/honeypot.py"
    "app/mqtt_client.py"
    "app/ai_agent.py"
    "app/config.py"
    "app/templates/index.html"
    "nginx/default.conf"
    "mosquitto/config/mosquitto.conf"
    "docker-compose.yml"
)

MISSING_FILES=0
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo -e "${RED}✗ 缺少文件: $file${NC}"
        MISSING_FILES=1
    else
        echo -e "${GREEN}✓ $file${NC}"
    fi
done

# 检查 templates 目录
if [ ! -d "app/templates" ] || [ -z "$(ls -A app/templates/)" ]; then
    echo -e "${RED}✗ app/templates/ 目录为空或不存在${NC}"
    MISSING_FILES=1
else
    echo -e "${GREEN}✓ app/templates/${NC}"
fi

if [ $MISSING_FILES -eq 1 ]; then
    echo ""
    echo -e "${RED}错误: 缺少必要的文件！${NC}"
    echo -e "${YELLOW}请确保已上传以下文件到服务器：${NC}"
    echo "  - app/Dockerfile"
    echo "  - app/requirements.txt"
    echo "  - app/app.py"
    echo "  - app/templates/*.html"
    echo ""
    exit 1
fi

echo -e "${GREEN}文件检查通过${NC}"

# ========== 检查/创建 .env 文件 ==========
echo ""
echo -e "${YELLOW}[2/6] 检查环境变量配置...${NC}"

if [ ! -f .env ]; then
    echo -e "${YELLOW}警告: .env 文件不存在，创建模板...${NC}"
    cat > .env << EOF
# MQTT 配置
MQTT_USERNAME=wifiwarden
MQTT_PASSWORD=YOUR_MQTT_PASSWORD

# AI 智能体 (DeepSeek 官方，可选，不填不影响系统运行)
AI_API_KEY=
AI_BASE_URL=https://api.deepseek.com/v1
AI_MODEL=deepseek-chat
EOF
    echo -e "${RED}请先编辑 .env 文件设置正确的配置！${NC}"
    echo "vi .env"
    exit 1
fi

echo -e "${GREEN}环境变量配置存在${NC}"

# ========== 检查/创建 mosquitto 配置 ==========
echo ""
echo -e "${YELLOW}[3/6] 检查 MQTT 配置...${NC}"

echo -e "${GREEN}MQTT 配置已存在（mosquitto.conf 由项目提供）${NC}"

echo -e "${GREEN}MQTT 配置完成${NC}"

# ========== 检查SSL证书 ==========
echo ""
echo -e "${YELLOW}[4/6] 检查 SSL 证书...${NC}"

if [ ! -f nginx/certs/cert.pem ] || [ ! -f nginx/certs/key.pem ]; then
    echo -e "${RED}警告: SSL证书文件不存在！${NC}"
    echo "请将证书文件放置到 nginx/certs/ 目录:"
    echo "  - cert.pem (证书)"
    echo "  - key.pem (私钥)"
    exit 1
fi

echo -e "${GREEN}SSL 证书检查通过${NC}"

# ========== 停止旧容器 ==========
echo ""
echo -e "${YELLOW}[5/6] 停止旧容器...${NC}"
$DC_CMD down --remove-orphans 2>/dev/null || true
echo -e "${GREEN}清理完成${NC}"

# ========== 构建并启动 ==========
echo ""
echo -e "${YELLOW}[6/6] 构建并启动服务...${NC}"
echo -e "${GREEN}开始构建Docker镜像（首次可能需要几分钟）...${NC}"
$DC_CMD up -d --build

echo ""
echo -e "${GREEN}=========================================="
echo "部署完成！"
echo "==========================================${NC}"
echo ""
echo "服务状态:"
$DC_CMD ps
echo ""
echo "Web控制台: https://你的域名"
echo "MQTT端口: 1883"
echo ""
echo "查看日志: $DC_CMD logs -f web"
echo "停止服务: $DC_CMD down"
