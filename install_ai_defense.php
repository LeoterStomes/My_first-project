<?php
/**
 * AI自适应防御决策系统安装脚本
 */

// 检查是否已安装
if (file_exists('ai_defense_installed.txt')) {
    die('AI防御系统已经安装过了。如需重新安装，请删除 ai_defense_installed.txt 文件。');
}

// 检查PHP版本 - 降低到7.3
if (version_compare(PHP_VERSION, '7.3.0', '<')) {
    die('需要PHP 7.3或更高版本。当前版本: ' . PHP_VERSION);
}

// 检查必要的扩展
$required_extensions = ['mysqli', 'json', 'session'];
$missing_extensions = [];

foreach ($required_extensions as $ext) {
    if (!extension_loaded($ext)) {
        $missing_extensions[] = $ext;
    }
}

if (!empty($missing_extensions)) {
    die('缺少必要的PHP扩展: ' . implode(', ', $missing_extensions));
}

// 检查文件权限
$writable_files = [
    'user_actions.log',
    'ai_defense_logs/',
    'uploads/'
];

foreach ($writable_files as $file) {
    if (file_exists($file) && !is_writable($file)) {
        die("文件 {$file} 不可写，请检查权限。");
    }
}

// 创建必要的目录
$directories = [
    'ai_defense_logs',
    'uploads',
    'backups'
];

foreach ($directories as $dir) {
    if (!file_exists($dir)) {
        if (!mkdir($dir, 0755, true)) {
            die("无法创建目录: {$dir}");
        }
    }
}

// 数据库连接测试
require_once 'db.php';

if ($conn->connect_error) {
    die('数据库连接失败: ' . $conn->connect_error);
}

// 执行数据库安装
$install_sql = file_get_contents('ai_defense_database.sql');
if (!$install_sql) {
    die('无法读取数据库安装文件: ai_defense_database.sql');
}

// 分割SQL语句并执行
$sql_statements = explode(';', $install_sql);
$success_count = 0;
$error_count = 0;

foreach ($sql_statements as $sql) {
    $sql = trim($sql);
    if (empty($sql)) continue;
    
    if ($conn->query($sql)) {
        $success_count++;
    } else {
        $error_count++;
        echo "SQL错误: " . $conn->error . "\n";
        echo "SQL语句: " . $sql . "\n\n";
    }
}

echo "数据库安装完成:\n";
echo "成功执行: {$success_count} 条语句\n";
echo "失败: {$error_count} 条语句\n\n";

// 创建配置文件
$config_content = "<?php
/**
 * AI防御系统配置文件
 * 生成时间: " . date('Y-m-d H:i:s') . "
 */

// 系统配置
define('AI_DEFENSE_ENABLED', true);
define('AI_DEFENSE_LOG_LEVEL', 'INFO');
define('AI_DEFENSE_MAX_LOG_SIZE', 10485760); // 10MB

// 威胁检测配置
define('THREAT_DETECTION_ENABLED', true);
define('AUTO_BLOCK_ENABLED', true);
define('EMERGENCY_MODE_ENABLED', false);

// 速率限制配置
define('RATE_LIMIT_REQUESTS', 100);
define('RATE_LIMIT_WINDOW', 3600); // 1小时

// 封禁配置
define('BLOCK_DURATION', 86400); // 24小时
define('MAX_THREAT_SCORE', 100);

// 日志配置
define('LOG_RETENTION_DAYS', 30);

// 通知配置
define('ENABLE_EMAIL_NOTIFICATIONS', false);
define('ADMIN_EMAIL', 'admin@example.com');

// 威胁情报配置
define('ENABLE_THREAT_INTELLIGENCE', true);
define('THREAT_INTELLIGENCE_API_KEY', '');

// 自动修复配置
define('AUTO_FIX_ENABLED', true);
define('AUTO_FIX_BACKUP_ENABLED', true);

// 系统健康检查
define('HEALTH_CHECK_INTERVAL', 300); // 5分钟
define('HEALTH_CHECK_ENABLED', true);
?>";

// 配置文件功能已集成到deepseek_config.php中
echo "✅ 配置文件功能已集成到deepseek_config.php中\n";

// 创建.htaccess文件来集成中间件
$htaccess_content = "RewriteEngine On

# AI防御系统中间件集成
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule ^(.*)$ ai_defense_middleware.php [L]

# 安全头设置
<IfModule mod_headers.c>
    Header always set X-Content-Type-Options nosniff
    Header always set X-Frame-Options DENY
    Header always set X-XSS-Protection \"1; mode=block\"
    Header always set Referrer-Policy \"strict-origin-when-cross-origin\"
    Header always set Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:;\"
</IfModule>

# 防止访问敏感文件
<Files \"*.log\">
    Order allow,deny
    Deny from all
</Files>

<Files \"*.sql\">
    Order allow,deny
    Deny from all
</Files>

<Files \"*.php\">
    <RequireAll>
        Require all granted
    </RequireAll>
</Files>

# 错误页面
ErrorDocument 403 /error/403.html
ErrorDocument 404 /error/404.html
ErrorDocument 500 /error/500.html

# 压缩设置
<IfModule mod_deflate.c>
    AddOutputFilterByType DEFLATE text/plain
    AddOutputFilterByType DEFLATE text/html
    AddOutputFilterByType DEFLATE text/xml
    AddOutputFilterByType DEFLATE text/css
    AddOutputFilterByType DEFLATE application/xml
    AddOutputFilterByType DEFLATE application/xhtml+xml
    AddOutputFilterByType DEFLATE application/rss+xml
    AddOutputFilterByType DEFLATE application/javascript
    AddOutputFilterByType DEFLATE application/x-javascript
</IfModule>

# 缓存设置
<IfModule mod_expires.c>
    ExpiresActive on
    ExpiresByType text/css \"access plus 1 year\"
    ExpiresByType application/javascript \"access plus 1 year\"
    ExpiresByType image/png \"access plus 1 year\"
    ExpiresByType image/jpg \"access plus 1 year\"
    ExpiresByType image/jpeg \"access plus 1 year\"
    ExpiresByType image/gif \"access plus 1 year\"
    ExpiresByType image/ico \"access plus 1 year\"
</IfModule>
";

if (file_put_contents('.htaccess', $htaccess_content)) {
    echo ".htaccess文件创建成功\n";
} else {
    echo "警告: 无法创建.htaccess文件\n";
}

// 安装完成标记功能已移除
echo "✅ 安装完成\n";

// 创建示例测试脚本
$test_script = "<?php
/**
 * AI防御系统测试脚本
 */

require_once 'ai_defense_system.php';

echo \"=== AI防御系统测试 ===\\n\";

// 测试威胁检测
echo \"1. 测试威胁检测...\\n\";
\$ai_defense = new AIDefenseSystem(\$conn);

// 模拟正常请求
\$normal_request = 'username=test&password=123456';
\$threat_analysis = \$ai_defense->detectThreat(\$normal_request);
echo \"正常请求威胁等级: \" . \$threat_analysis['threat_level'] . \"\\n\";

// 模拟恶意请求
\$malicious_request = 'username=admin\' OR 1=1--&password=test';
\$threat_analysis = \$ai_defense->detectThreat(\$malicious_request);
echo \"恶意请求威胁等级: \" . \$threat_analysis['threat_level'] . \"\\n\";

// 测试系统状态
echo \"\\n2. 测试系统状态...\\n\";
\$status = \$ai_defense->getSystemStatus();
echo \"系统健康状态: \" . \$status['system_health'] . \"\\n\";
echo \"活跃威胁数量: \" . \$status['active_threats'] . \"\\n\";

echo \"\\n=== 测试完成 ===\\n\";
?>";

// 测试脚本功能已集成到演示页面中
echo "✅ 测试功能已集成到演示页面中\n";

// 创建使用说明
$readme_content = "# AI自适应防御决策系统

## 系统概述

AI自适应防御决策系统是一个智能化的网络安全防护解决方案，具备以下核心功能：

- 🤖 **AI威胁检测**: 基于机器学习的实时威胁识别
- 🛡️ **动态策略优化**: 自适应调整防御策略
- 🔧 **自动化漏洞修复**: 智能识别并修复安全漏洞
- 🚫 **威胁阻断**: 多层次威胁阻断机制
- 🔍 **攻击溯源**: 深度攻击链分析和溯源

## 安装完成

系统已成功安装到您的服务器上。以下是重要信息：

### 访问地址
- 管理仪表板: `http://your-domain/ai_defense_dashboard.php`
- API接口: `http://your-domain/ai_defense_api.php`
- 演示页面: `http://your-domain/admin_ai_defense.php`

### 默认配置
- 威胁检测: 已启用
- 自动封禁: 已启用
- 紧急模式: 已禁用
- 速率限制: 100请求/小时

### 安全建议
1. 立即修改默认密码
2. 配置邮件通知
3. 定期备份数据库
4. 监控系统日志
5. 更新威胁情报库

### 文件说明
- `ai_defense_system.php`: 核心防御系统
- `ai_defense_middleware.php`: 中间件集成
- `ai_defense_dashboard.php`: 管理界面
- `ai_defense_api.php`: API接口
- `deepseek_config.php`: DeepSeek AI配置
- `ai_defense_database.sql`: 数据库结构

### 集成到现有应用

在您的PHP文件开头添加：

```php
require_once 'ai_defense_middleware.php';
\$middleware = new AIDefenseMiddleware(\$conn);
\$middleware->processRequest();
```

### 系统监控

系统会自动记录以下信息：
- 所有请求日志
- 攻击检测记录
- 策略执行情况
- 系统性能指标

### 技术支持

如遇到问题，请检查：
1. 数据库连接是否正常
2. 文件权限是否正确
3. PHP扩展是否完整
4. 系统日志是否有错误

## 更新日志

### v1.0.0 (当前版本)
- 初始版本发布
- 基础威胁检测功能
- 自动化防御机制
- 管理仪表板
- API接口支持

---

**注意**: 请定期更新系统和威胁情报库以确保最佳防护效果。
";

if (file_put_contents('AI_DEFENSE_README.md', $readme_content)) {
    echo "使用说明创建成功: AI_DEFENSE_README.md\n";
} else {
    echo "警告: 无法创建使用说明\n";
}

echo "\n=== AI自适应防御决策系统安装完成 ===\n";
echo "安装时间: " . date('Y-m-d H:i:s') . "\n";
echo "安装位置: " . __DIR__ . "\n";
echo "\n下一步操作:\n";
echo "1. 访问 http://your-domain/ai_defense_dashboard.php 查看管理界面\n";
echo "2. 访问 http://your-domain/admin_ai_defense.php 查看系统功能\n";
echo "3. 阅读 AI_DEFENSE_README.md 了解详细使用说明\n";
echo "4. 根据需要调整 deepseek_config.php 中的配置\n";
echo "\n安全提示:\n";
echo "- 请立即修改默认密码\n";
echo "- 定期备份数据库\n";
echo "- 监控系统日志\n";
echo "- 更新威胁情报库\n";
echo "\n感谢使用AI自适应防御决策系统！\n";
?> 