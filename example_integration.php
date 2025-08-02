<?php
/**
 * AI自适应防御决策系统集成示例
 * 展示如何将AI防御系统集成到现有应用中
 */

// 1. 基础集成示例
echo "=== AI防御系统集成示例 ===\n\n";

// 引入必要的文件
require_once 'db.php';
require_once 'ai_defense_system.php';
require_once 'ai_defense_middleware.php';

// 初始化AI防御中间件（在Web环境中使用）
// $middleware = new AIDefenseMiddleware($conn);
// $request_allowed = $middleware->processRequest();
// if (!$request_allowed) {
//     exit;
// }

// 在命令行环境中，我们直接初始化AI防御系统
$ai_defense = new AIDefenseSystem($conn);

// 2. 在现有应用中集成AI防御
echo "=== 现有应用集成示例 ===\n\n";

// 示例：用户登录页面集成
class SecureLoginPage {
    private $ai_defense;
    private $conn;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->ai_defense = new AIDefenseSystem($conn);
    }
    
    public function handleLogin($username, $password) {
        // 构建请求数据用于威胁检测
        $request_data = json_encode([
            'username' => $username,
            'password' => $password,
            'action' => 'login',
            'timestamp' => time()
        ]);
        
        // AI威胁检测
        $threat_analysis = $this->ai_defense->detectThreat($request_data);
        
        echo "威胁检测结果:\n";
        echo "- 威胁等级: " . $threat_analysis['threat_level'] . "\n";
        echo "- 威胁评分: " . $threat_analysis['score'] . "\n";
        echo "- 检测到的威胁: " . implode(', ', $threat_analysis['detected_threats']) . "\n\n";
        
        // 根据威胁等级决定处理方式
        switch ($threat_analysis['threat_level']) {
            case 'critical':
                echo "🚨 检测到严重威胁，拒绝登录\n";
                return false;
                
            case 'high':
                echo "⚠️ 检测到高风险威胁，需要额外验证\n";
                return $this->requireAdditionalVerification($username);
                
            case 'medium':
                echo "🔍 检测到中等风险，记录日志\n";
                $this->logSuspiciousActivity($username, $threat_analysis);
                return $this->processLogin($username, $password);
                
            case 'low':
            default:
                echo "✅ 威胁等级较低，正常处理\n";
                return $this->processLogin($username, $password);
        }
    }
    
    private function requireAdditionalVerification($username) {
        echo "需要额外验证: 发送验证码到用户邮箱\n";
        // 这里可以实现发送验证码、短信验证等
        return true;
    }
    
    private function logSuspiciousActivity($username, $threat_analysis) {
        echo "记录可疑活动: {$username}\n";
        // 记录到安全日志
    }
    
    private function processLogin($username, $password) {
        echo "处理正常登录: {$username}\n";
        // 正常的登录逻辑
        return true;
    }
}

// 3. 自动化漏洞修复示例
echo "=== 自动化漏洞修复示例 ===\n\n";

class VulnerabilityScanner {
    private $ai_defense;
    
    public function __construct($ai_defense) {
        $this->ai_defense = $ai_defense;
    }
    
    public function scanAndFix($file_path) {
        echo "扫描文件: {$file_path}\n";
        
        // 模拟发现漏洞
        $vulnerabilities = [
            [
                'type' => 'sql_injection',
                'file' => $file_path,
                'line' => 15,
                'description' => '发现SQL注入漏洞'
            ],
            [
                'type' => 'xss',
                'file' => $file_path,
                'line' => 23,
                'description' => '发现XSS漏洞'
            ]
        ];
        
        foreach ($vulnerabilities as $vuln) {
            echo "发现漏洞: {$vuln['description']}\n";
            
            // 使用AI防御系统自动修复
            $fix_action = $this->ai_defense->autoFixVulnerability($vuln);
            
            echo "修复操作:\n";
            echo "- {$fix_action['action']}: {$fix_action['description']}\n";
            echo "\n";
        }
    }
}

// 4. 攻击溯源示例
echo "=== 攻击溯源示例 ===\n\n";

class AttackTracer {
    private $ai_defense;
    
    public function __construct($ai_defense) {
        $this->ai_defense = $ai_defense;
    }
    
    public function traceAttack($attack_data) {
        echo "开始攻击溯源分析...\n";
        
        $trace_result = $this->ai_defense->traceAttack($attack_data);
        
        echo "溯源结果:\n";
        echo "- 攻击链长度: " . count($trace_result['attack_chain']) . "\n";
        echo "- 攻击模式: " . $trace_result['source_analysis']['attack_pattern'] . "\n";
        echo "- 建议措施:\n";
        foreach ($trace_result['recommendations'] as $recommendation) {
            echo "  * {$recommendation}\n";
        }
        echo "\n";
    }
}

// 5. 实际使用示例
echo "=== 实际使用示例 ===\n\n";

// 初始化AI防御系统
$ai_defense = new AIDefenseSystem($conn);

// 初始化组件
$secure_login = new SecureLoginPage($conn);
$vuln_scanner = new VulnerabilityScanner($ai_defense);
$attack_tracer = new AttackTracer($ai_defense);

// 模拟登录尝试
echo "模拟登录尝试:\n";
$login_result = $secure_login->handleLogin('admin', 'password123');
echo "登录结果: " . ($login_result ? '成功' : '失败') . "\n\n";

// 模拟恶意登录尝试
echo "模拟恶意登录尝试:\n";
$malicious_result = $secure_login->handleLogin("admin' OR 1=1--", 'password');
echo "恶意登录结果: " . ($malicious_result ? '成功' : '失败') . "\n\n";

// 扫描漏洞
echo "扫描漏洞:\n";
$vuln_scanner->scanAndFix('example_file.php');

// 攻击溯源
echo "攻击溯源:\n";
$attack_data = [
    'client_ip' => '192.168.1.100',
    'user_agent' => 'Mozilla/5.0 (compatible; Bot/1.0)',
    'threat_level' => 'high'
];
$attack_tracer->traceAttack($attack_data);

// 6. 系统状态监控
echo "=== 系统状态监控 ===\n\n";

$system_status = $ai_defense->getSystemStatus();
echo "系统状态:\n";
echo "- 活跃威胁: " . $system_status['active_threats'] . "\n";
echo "- 封禁IP数量: " . $system_status['blocked_ips_count'] . "\n";
echo "- 防御策略数量: " . $system_status['defense_strategies_count'] . "\n";
echo "- 攻击模式数量: " . $system_status['attack_patterns_count'] . "\n";
echo "- 系统健康状态: " . $system_status['system_health'] . "\n\n";

// 7. 集成到现有应用的完整示例
echo "=== 完整集成示例 ===\n\n";

// 在现有PHP文件开头添加以下代码：
$integration_code = '
<?php
// 1. 引入AI防御系统
require_once "ai_defense_middleware.php";

// 2. 初始化中间件
$middleware = new AIDefenseMiddleware($conn);

// 3. 处理请求（自动检测威胁）
$request_allowed = $middleware->processRequest();

if (!$request_allowed) {
    // 请求被阻断，脚本终止
    exit;
}

// 4. 继续正常的应用逻辑
// ... 您的应用代码 ...

// 5. 在关键操作点添加额外检查
if (isset($_POST["login"])) {
    $username = $_POST["username"];
    $password = $_POST["password"];
    
    // 使用AI防御系统检查
    $request_data = json_encode($_POST);
    $threat_analysis = $ai_defense->detectThreat($request_data);
    
    if ($threat_analysis["threat_level"] === "critical") {
        die("检测到严重威胁，拒绝访问");
    }
    
    // 继续登录逻辑
    // ...
}
?>
';

echo "集成代码示例:\n";
echo $integration_code;

echo "\n=== 集成完成 ===\n";
echo "AI防御系统已成功集成到您的应用中！\n";
echo "系统将自动检测和阻止各种威胁。\n";
echo "您可以通过管理仪表板监控系统状态。\n";
?> 