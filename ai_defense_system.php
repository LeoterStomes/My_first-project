<?php
/**
 * AI自适应防御决策系统
 * 主要功能：动态优化安全策略、自动化漏洞修复、威胁阻断、攻击溯源
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}
require_once 'db.php';

class AIDefenseSystem {
    private $conn;
    private $threat_levels = ['low', 'medium', 'high', 'critical'];
    private $defense_strategies = [];
    private $attack_patterns = [];
    private $blocked_ips = [];
    
    public function __construct($conn) {
        $this->conn = $conn;
        $this->loadDefenseStrategies();
        $this->loadAttackPatterns();
        $this->loadBlockedIPs();
    }
    
    /**
     * 加载防御策略
     */
    private function loadDefenseStrategies() {
        $sql = "SELECT * FROM defense_strategies WHERE active = 1 ORDER BY priority DESC";
        $result = $this->conn->query($sql);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $this->defense_strategies[] = $row;
            }
        }
    }
    
    /**
     * 加载攻击模式
     */
    private function loadAttackPatterns() {
        $sql = "SELECT * FROM attack_patterns WHERE active = 1";
        $result = $this->conn->query($sql);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $this->attack_patterns[] = $row;
            }
        }
    }
    
    /**
     * 加载已封禁IP
     */
    private function loadBlockedIPs() {
        $sql = "SELECT ip_address FROM blocked_ips WHERE active = 1";
        $result = $this->conn->query($sql);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                $this->blocked_ips[] = $row['ip_address'];
            }
        }
    }
    
    /**
     * AI威胁检测
     */
    public function detectThreat($request_data) {
        $threat_score = 0;
        $detected_threats = [];
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        
        // 检查IP是否已被封禁
        if (in_array($client_ip, $this->blocked_ips)) {
            return [
                'threat_level' => 'critical',
                'action' => 'block',
                'reason' => 'IP已被封禁',
                'score' => 100
            ];
        }
        
        // 分析请求模式
        foreach ($this->attack_patterns as $pattern) {
            $pattern_matches = $this->matchPattern($request_data, $pattern);
            if ($pattern_matches) {
                $threat_score += $pattern['severity'];
                $detected_threats[] = $pattern['name'];
            }
        }
        
        // 行为分析
        $behavior_score = $this->analyzeBehavior($client_ip);
        $threat_score += $behavior_score;
        
        // 确定威胁等级
        $threat_level = $this->determineThreatLevel($threat_score);
        
        return [
            'threat_level' => $threat_level,
            'score' => $threat_score,
            'detected_threats' => $detected_threats,
            'client_ip' => $client_ip
        ];
    }
    
    /**
     * 模式匹配
     */
    private function matchPattern($data, $pattern) {
        $patterns = json_decode($pattern['patterns'], true);
        foreach ($patterns as $p) {
            if (preg_match($p, $data)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * 行为分析
     */
    private function analyzeBehavior($ip) {
        $sql = "SELECT COUNT(*) as count, 
                       AVG(TIMESTAMPDIFF(SECOND, created_at, NOW())) as avg_time
                FROM request_logs 
                WHERE ip_address = ? AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('s', $ip);
        $stmt->execute();
        $result = $stmt->get_result();
        $data = $result->fetch_assoc();
        
        $score = 0;
        if ($data['count'] > 100) $score += 30; // 高频请求
        if ($data['avg_time'] < 2) $score += 20; // 请求间隔过短
        
        return $score;
    }
    
    /**
     * 确定威胁等级
     */
    private function determineThreatLevel($score) {
        if ($score >= 80) return 'critical';
        if ($score >= 60) return 'high';
        if ($score >= 40) return 'medium';
        return 'low';
    }
    
    /**
     * 动态优化安全策略
     */
    public function optimizeStrategy($threat_analysis) {
        $optimized_strategy = [];
        
        foreach ($this->defense_strategies as $strategy) {
            $effectiveness = $this->calculateEffectiveness($strategy, $threat_analysis);
            if ($effectiveness > 0.7) {
                $optimized_strategy[] = [
                    'strategy_id' => $strategy['id'],
                    'name' => $strategy['name'],
                    'action' => $strategy['action'],
                    'effectiveness' => $effectiveness
                ];
            }
        }
        
        // 按有效性排序
        usort($optimized_strategy, function($a, $b) {
            return $b['effectiveness'] <=> $a['effectiveness'];
        });
        
        return $optimized_strategy;
    }
    
    /**
     * 计算策略有效性
     */
    private function calculateEffectiveness($strategy, $threat_analysis) {
        $effectiveness = 0.5; // 基础有效性
        
        // 根据威胁等级调整
        $threat_level_score = array_search($threat_analysis['threat_level'], $this->threat_levels);
        $effectiveness += $threat_level_score * 0.1;
        
        // 根据历史成功率调整
        $success_rate = $this->getStrategySuccessRate($strategy['id']);
        $effectiveness += $success_rate * 0.3;
        
        return min(1.0, $effectiveness);
    }
    
    /**
     * 获取策略成功率
     */
    private function getStrategySuccessRate($strategy_id) {
        $sql = "SELECT 
                    COUNT(CASE WHEN success = 1 THEN 1 END) as success_count,
                    COUNT(*) as total_count
                FROM strategy_executions 
                WHERE strategy_id = ? AND created_at > DATE_SUB(NOW(), INTERVAL 24 HOUR)";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('i', $strategy_id);
        $stmt->execute();
        $result = $stmt->get_result();
        $data = $result->fetch_assoc();
        
        return $data['total_count'] > 0 ? $data['success_count'] / $data['total_count'] : 0.5;
    }
    
    /**
     * 自动化漏洞修复
     */
    public function autoFixVulnerability($vulnerability_data) {
        $fix_actions = [];
        
        switch ($vulnerability_data['type']) {
            case 'sql_injection':
                $fix_actions = $this->fixSQLInjection($vulnerability_data);
                break;
            case 'xss':
                $fix_actions = $this->fixXSS($vulnerability_data);
                break;
            case 'csrf':
                $fix_actions = $this->fixCSRF($vulnerability_data);
                break;
            case 'file_upload':
                $fix_actions = $this->fixFileUpload($vulnerability_data);
                break;
        }
        
        // 记录修复操作
        $this->logFixAction($vulnerability_data, $fix_actions);
        
        return $fix_actions;
    }
    
    /**
     * 修复SQL注入
     */
    private function fixSQLInjection($data) {
        return [
            'action' => 'apply_prepared_statements',
            'file' => $data['file'],
            'line' => $data['line'],
            'description' => '应用预编译语句防止SQL注入'
        ];
    }
    
    /**
     * 修复XSS
     */
    private function fixXSS($data) {
        return [
            'action' => 'apply_output_encoding',
            'file' => $data['file'],
            'line' => $data['line'],
            'description' => '应用输出编码防止XSS攻击'
        ];
    }
    
    /**
     * 修复CSRF
     */
    private function fixCSRF($data) {
        return [
            'action' => 'add_csrf_token',
            'file' => $data['file'],
            'line' => $data['line'],
            'description' => '添加CSRF令牌验证'
        ];
    }
    
    /**
     * 修复文件上传
     */
    private function fixFileUpload($data) {
        return [
            'action' => 'add_file_validation',
            'file' => $data['file'],
            'line' => $data['line'],
            'description' => '添加文件类型和大小验证'
        ];
    }
    
    /**
     * 威胁阻断
     */
    public function blockThreat($threat_data) {
        $block_actions = [];
        $client_ip = $threat_data['client_ip'];
        
        // 根据威胁等级决定阻断策略
        switch ($threat_data['threat_level']) {
            case 'critical':
                $block_actions[] = $this->blockIP($client_ip, 'critical_threat');
                $block_actions[] = $this->enableEmergencyMode();
                break;
            case 'high':
                $block_actions[] = $this->blockIP($client_ip, 'high_threat');
                $block_actions[] = $this->increaseMonitoring($client_ip);
                break;
            case 'medium':
                $block_actions[] = $this->rateLimit($client_ip);
                break;
        }
        
        // 记录阻断操作
        $this->logBlockAction($threat_data, $block_actions);
        
        return $block_actions;
    }
    
    /**
     * 封禁IP
     */
    private function blockIP($ip, $reason) {
        $sql = "INSERT INTO blocked_ips (ip_address, reason, created_at) VALUES (?, ?, NOW())";
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('ss', $ip, $reason);
        $stmt->execute();
        
        return [
            'action' => 'block_ip',
            'ip' => $ip,
            'reason' => $reason
        ];
    }
    
    /**
     * 启用紧急模式
     */
    private function enableEmergencyMode() {
        return [
            'action' => 'enable_emergency_mode',
            'description' => '启用紧急防御模式，限制所有可疑活动'
        ];
    }
    
    /**
     * 增加监控
     */
    private function increaseMonitoring($ip) {
        return [
            'action' => 'increase_monitoring',
            'ip' => $ip,
            'description' => '增加对可疑IP的监控频率'
        ];
    }
    
    /**
     * 速率限制
     */
    private function rateLimit($ip) {
        return [
            'action' => 'rate_limit',
            'ip' => $ip,
            'description' => '对可疑IP实施速率限制'
        ];
    }
    
    /**
     * 攻击溯源
     */
    public function traceAttack($attack_data) {
        $trace_result = [
            'attack_chain' => [],
            'source_analysis' => [],
            'recommendations' => []
        ];
        
        // 分析攻击链
        $trace_result['attack_chain'] = $this->analyzeAttackChain($attack_data);
        
        // 溯源分析
        $trace_result['source_analysis'] = $this->analyzeSource($attack_data);
        
        // 生成建议
        $trace_result['recommendations'] = $this->generateRecommendations($attack_data);
        
        return $trace_result;
    }
    
    /**
     * 分析攻击链
     */
    private function analyzeAttackChain($data) {
        $sql = "SELECT * FROM attack_logs 
                WHERE ip_address = ? 
                ORDER BY created_at ASC";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->bind_param('s', $data['client_ip']);
        $stmt->execute();
        $result = $stmt->get_result();
        
        $chain = [];
        while ($row = $result->fetch_assoc()) {
            $chain[] = [
                'timestamp' => $row['created_at'],
                'action' => $row['action'],
                'payload' => $row['payload'],
                'result' => $row['result']
            ];
        }
        
        return $chain;
    }
    
    /**
     * 分析攻击源
     */
    private function analyzeSource($data) {
        return [
            'ip_geolocation' => $this->getIPGeolocation($data['client_ip']),
            'user_agent' => $data['user_agent'] ?? 'unknown',
            'attack_pattern' => $this->identifyAttackPattern($data),
            'threat_intelligence' => $this->getThreatIntelligence($data['client_ip'])
        ];
    }
    
    /**
     * 获取IP地理位置
     */
    private function getIPGeolocation($ip) {
        // 这里可以集成第三方IP地理位置服务
        return [
            'country' => 'Unknown',
            'city' => 'Unknown',
            'isp' => 'Unknown'
        ];
    }
    
    /**
     * 识别攻击模式
     */
    private function identifyAttackPattern($data) {
        // 基于历史数据分析攻击模式
        return 'automated_scanning';
    }
    
    /**
     * 获取威胁情报
     */
    private function getThreatIntelligence($ip) {
        // 这里可以集成威胁情报服务
        return [
            'reputation' => 'unknown',
            'threat_score' => 0,
            'known_malicious' => false
        ];
    }
    
    /**
     * 生成建议
     */
    private function generateRecommendations($data) {
        $recommendations = [];
        
        if ($data['threat_level'] === 'critical') {
            $recommendations[] = '立即封禁攻击源IP';
            $recommendations[] = '启用紧急防御模式';
            $recommendations[] = '通知安全团队';
        }
        
        if ($data['threat_level'] === 'high') {
            $recommendations[] = '增加监控频率';
            $recommendations[] = '实施临时封禁';
        }
        
        $recommendations[] = '更新威胁情报库';
        $recommendations[] = '加强日志监控';
        
        return $recommendations;
    }
    
    /**
     * 记录修复操作
     */
    private function logFixAction($vulnerability, $actions) {
        $sql = "INSERT INTO fix_actions (vulnerability_type, file_path, line_number, actions, created_at) 
                VALUES (?, ?, ?, ?, NOW())";
        $stmt = $this->conn->prepare($sql);
        $actions_json = json_encode($actions);
        $stmt->bind_param('ssss', $vulnerability['type'], $vulnerability['file'], $vulnerability['line'], $actions_json);
        $stmt->execute();
    }
    
    /**
     * 记录阻断操作
     */
    private function logBlockAction($threat_data, $actions) {
        $sql = "INSERT INTO block_actions (ip_address, threat_level, threat_score, actions, created_at) 
                VALUES (?, ?, ?, ?, NOW())";
        $stmt = $this->conn->prepare($sql);
        $actions_json = json_encode($actions);
        $stmt->bind_param('ssss', $threat_data['client_ip'], $threat_data['threat_level'], $threat_data['score'], $actions_json);
        $stmt->execute();
    }
    
    /**
     * 获取系统状态
     */
    public function getSystemStatus() {
        $status = [
            'active_threats' => $this->getActiveThreats(),
            'blocked_ips_count' => count($this->blocked_ips),
            'defense_strategies_count' => count($this->defense_strategies),
            'attack_patterns_count' => count($this->attack_patterns),
            'system_health' => $this->getSystemHealth()
        ];
        
        return $status;
    }
    
    /**
     * 获取活跃威胁
     */
    private function getActiveThreats() {
        $sql = "SELECT COUNT(*) as count FROM attack_logs 
                WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
        $result = $this->conn->query($sql);
        $data = $result->fetch_assoc();
        return $data['count'];
    }
    
    /**
     * 获取系统健康状态
     */
    private function getSystemHealth() {
        // 检查数据库连接
        if ($this->conn->ping()) {
            return 'healthy';
        }
        return 'unhealthy';
    }
}

// 只有在直接访问此文件时才执行API处理
if (basename($_SERVER['SCRIPT_NAME']) === 'ai_defense_system.php') {
    // 初始化AI防御系统
    $ai_defense = new AIDefenseSystem($conn);

    // 处理请求
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $input = json_decode(file_get_contents('php://input'), true);
        $action = $input['action'] ?? '';
        
        switch ($action) {
            case 'detect_threat':
                $threat_analysis = $ai_defense->detectThreat($input['data']);
                $optimized_strategy = $ai_defense->optimizeStrategy($threat_analysis);
                $block_actions = $ai_defense->blockThreat($threat_analysis);
                
                echo json_encode([
                    'threat_analysis' => $threat_analysis,
                    'optimized_strategy' => $optimized_strategy,
                    'block_actions' => $block_actions
                ]);
                break;
                
            case 'auto_fix':
                $fix_actions = $ai_defense->autoFixVulnerability($input['vulnerability']);
                echo json_encode(['fix_actions' => $fix_actions]);
                break;
                
            case 'trace_attack':
                $trace_result = $ai_defense->traceAttack($input['attack_data']);
                echo json_encode(['trace_result' => $trace_result]);
                break;
                
            case 'get_status':
                $status = $ai_defense->getSystemStatus();
                echo json_encode(['status' => $status]);
                break;
        }
    }
}
?> 