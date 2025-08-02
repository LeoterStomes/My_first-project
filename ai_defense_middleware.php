<?php
/**
 * AI自适应防御决策系统中间件
 * 自动集成到现有应用中，提供实时威胁检测和防护
 */

require_once 'db.php';
require_once 'ai_defense_system.php';

class AIDefenseMiddleware {
    private $ai_defense;
    private $conn;
    private $config;
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->ai_defense = new AIDefenseSystem($conn);
        $this->loadConfig();
    }
    
    /**
     * 加载系统配置
     */
    private function loadConfig() {
        $sql = "SELECT config_key, config_value FROM system_config";
        $result = $this->conn->query($sql);
        $this->config = [];
        
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $this->config[$row['config_key']] = $row['config_value'];
            }
        }
    }
    
    /**
     * 处理请求
     */
    public function processRequest() {
        // 检查是否启用威胁检测
        if (!isset($this->config['threat_detection_enabled']) || $this->config['threat_detection_enabled'] != '1') {
            return true; // 跳过检测
        }
        
        $client_ip = $this->getClientIP();
        $request_data = $this->getRequestData();
        
        // 记录请求日志
        $this->logRequest($client_ip, $request_data);
        
        // 威胁检测
        $threat_analysis = $this->ai_defense->detectThreat($request_data);
        
        // 如果检测到威胁，记录攻击日志
        if ($threat_analysis['threat_level'] !== 'low') {
            $this->logAttack($client_ip, $threat_analysis);
        }
        
        // 根据威胁等级采取相应措施
        return $this->handleThreat($threat_analysis);
    }
    
    /**
     * 获取客户端IP
     */
    private function getClientIP() {
        $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($ip_keys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    }
    
    /**
     * 获取请求数据
     */
    private function getRequestData() {
        $data = [];
        
        // 合并GET、POST、COOKIE数据
        $data = array_merge($_GET, $_POST, $_COOKIE);
        
        // 添加请求头信息
        $headers = function_exists('getallheaders') ? getallheaders() : [];
        if ($headers) {
            $data['headers'] = $headers;
        }
        
        // 添加用户代理
        $data['user_agent'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // 添加请求URI
        $data['request_uri'] = $_SERVER['REQUEST_URI'] ?? '';
        
        return json_encode($data);
    }
    
    /**
     * 记录请求日志
     */
    private function logRequest($ip_address, $request_data) {
        $sql = "INSERT INTO request_logs (ip_address, user_agent, request_method, request_uri, request_data, created_at) 
                VALUES (?, ?, ?, ?, ?, NOW())";
        
        $stmt = $this->conn->prepare($sql);
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $request_method = $_SERVER['REQUEST_METHOD'] ?? '';
        $request_uri = $_SERVER['REQUEST_URI'] ?? '';
        
        $stmt->bind_param('sssss', $ip_address, $user_agent, $request_method, $request_uri, $request_data);
        $stmt->execute();
    }
    
    /**
     * 记录攻击日志
     */
    private function logAttack($ip_address, $threat_analysis) {
        $sql = "INSERT INTO attack_logs (ip_address, attack_type, action, payload, threat_level, created_at) 
                VALUES (?, ?, ?, ?, ?, NOW())";
        
        $stmt = $this->conn->prepare($sql);
        $attack_type = implode(',', $threat_analysis['detected_threats']);
        $action = 'detected';
        $payload = json_encode($threat_analysis);
        $threat_level = $threat_analysis['threat_level'];
        
        $stmt->bind_param('sssss', $ip_address, $attack_type, $action, $payload, $threat_level);
        $stmt->execute();
    }
    
    /**
     * 处理威胁
     */
    private function handleThreat($threat_analysis) {
        $client_ip = $threat_analysis['client_ip'];
        
        switch ($threat_analysis['threat_level']) {
            case 'critical':
                // 立即阻断
                $this->blockIP($client_ip, 'critical_threat');
                $this->showBlockPage($client_ip, $threat_analysis);
                return false;
                
            case 'high':
                // 临时封禁
                $this->blockIP($client_ip, 'high_threat');
                $this->showWarningPage($client_ip, $threat_analysis);
                return false;
                
            case 'medium':
                // 速率限制
                if ($this->isRateLimited($client_ip)) {
                    $this->showRateLimitPage($client_ip);
                    return false;
                }
                break;
                
            case 'low':
            default:
                // 正常处理
                break;
        }
        
        return true;
    }
    
    /**
     * 封禁IP
     */
    private function blockIP($ip, $reason) {
        $block_duration = $this->config['block_duration'] ?? 86400; // 默认24小时
        $expires_at = date('Y-m-d H:i:s', time() + $block_duration);
        
        $sql = "INSERT INTO blocked_ips (ip_address, reason, expires_at, created_at) 
                VALUES (?, ?, ?, NOW()) 
                ON DUPLICATE KEY UPDATE 
                reason = VALUES(reason), 
                expires_at = VALUES(expires_at), 
                active = 1";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('sss', $ip, $reason, $expires_at);
        $stmt->execute();
    }
    
    /**
     * 检查速率限制
     */
    private function isRateLimited($ip) {
        $rate_limit_requests = $this->config['rate_limit_requests'] ?? 100;
        $rate_limit_window = $this->config['rate_limit_window'] ?? 3600;
        
        $sql = "SELECT COUNT(*) as count FROM request_logs 
                WHERE ip_address = ? AND created_at > DATE_SUB(NOW(), INTERVAL ? SECOND)";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('si', $ip, $rate_limit_window);
        $stmt->execute();
        $result = $stmt->get_result();
        $data = $result->fetch_assoc();
        
        return $data['count'] > $rate_limit_requests;
    }
    
    /**
     * 显示阻断页面
     */
    private function showBlockPage($ip, $threat_analysis) {
        http_response_code(403);
        ?>
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>访问被阻断</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .block-container {
                    text-align: center;
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                }
                .block-icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                }
                .block-title {
                    font-size: 24px;
                    margin-bottom: 10px;
                }
                .block-message {
                    font-size: 16px;
                    opacity: 0.9;
                    margin-bottom: 20px;
                }
                .block-details {
                    font-size: 12px;
                    opacity: 0.7;
                }
            </style>
        </head>
        <body>
            <div class="block-container">
                <div class="block-icon">🚫</div>
                <div class="block-title">访问被阻断</div>
                <div class="block-message">
                    检测到可疑活动，您的访问已被AI防御系统阻断。
                </div>
                <div class="block-details">
                    IP: <?php echo htmlspecialchars($ip); ?><br>
                    威胁等级: <?php echo strtoupper($threat_analysis['threat_level']); ?><br>
                    时间: <?php echo date('Y-m-d H:i:s'); ?>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    /**
     * 显示警告页面
     */
    private function showWarningPage($ip, $threat_analysis) {
        ?>
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>安全警告</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .warning-container {
                    text-align: center;
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                }
                .warning-icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                }
                .warning-title {
                    font-size: 24px;
                    margin-bottom: 10px;
                }
                .warning-message {
                    font-size: 16px;
                    opacity: 0.9;
                    margin-bottom: 20px;
                }
                .continue-button {
                    background: rgba(255,255,255,0.2);
                    color: white;
                    border: none;
                    padding: 10px 20px;
                    border-radius: 5px;
                    cursor: pointer;
                    font-size: 14px;
                }
            </style>
        </head>
        <body>
            <div class="warning-container">
                <div class="warning-icon">⚠️</div>
                <div class="warning-title">安全警告</div>
                <div class="warning-message">
                    检测到可疑活动，请确认您的操作是否正常。
                </div>
                <button class="continue-button" onclick="window.history.back()">返回上一页</button>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    /**
     * 显示速率限制页面
     */
    private function showRateLimitPage($ip) {
        http_response_code(429);
        ?>
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>请求过于频繁</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    background: linear-gradient(135deg, #ff6348 0%, #ffa502 100%);
                    color: white;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    margin: 0;
                }
                .rate-limit-container {
                    text-align: center;
                    background: rgba(255,255,255,0.1);
                    padding: 40px;
                    border-radius: 20px;
                    backdrop-filter: blur(10px);
                }
                .rate-limit-icon {
                    font-size: 64px;
                    margin-bottom: 20px;
                }
                .rate-limit-title {
                    font-size: 24px;
                    margin-bottom: 10px;
                }
                .rate-limit-message {
                    font-size: 16px;
                    opacity: 0.9;
                }
            </style>
        </head>
        <body>
            <div class="rate-limit-container">
                <div class="rate-limit-icon">⏱️</div>
                <div class="rate-limit-title">请求过于频繁</div>
                <div class="rate-limit-message">
                    您的请求频率过高，请稍后再试。
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    
    /**
     * 获取系统状态
     */
    public function getSystemStatus() {
        return $this->ai_defense->getSystemStatus();
    }
    
    /**
     * 应用漏洞修复
     */
    public function applyVulnerabilityFix($vulnerability_data) {
        return $this->ai_defense->autoFixVulnerability($vulnerability_data);
    }
    
    /**
     * 攻击溯源
     */
    public function traceAttack($attack_data) {
        return $this->ai_defense->traceAttack($attack_data);
    }
}

// 自动初始化中间件（如果直接访问此文件）
if (basename($_SERVER['SCRIPT_NAME']) === 'ai_defense_middleware.php') {
    $middleware = new AIDefenseMiddleware($conn);
    $middleware->processRequest();
}
?> 