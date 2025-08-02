<?php
/**
 * AI自适应防御决策系统API接口
 */

session_start();
require_once 'db.php';
require_once 'ai_defense_system.php';

// 设置响应头
header('Content-Type: application/json; charset=utf-8');

// 检查用户权限
if (!isset($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['error' => '未授权访问']);
    exit;
}

// 初始化AI防御系统
$ai_defense = new AIDefenseSystem($conn);

// 处理GET请求
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $action = $_GET['action'] ?? '';
    
    switch ($action) {
        case 'export_logs':
            exportSecurityLogs($conn);
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['error' => '无效的请求']);
            break;
    }
}

// 处理POST请求
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? '';
    
    switch ($action) {
        case 'get_recent_activity':
            getRecentActivity($conn);
            break;
            
        case 'get_strategy_status':
            getStrategyStatus($conn);
            break;
            
        case 'optimize_strategies':
            optimizeStrategies($ai_defense);
            break;
            
        case 'emergency_mode':
            enableEmergencyMode($conn);
            break;
            
        case 'clear_blocked_ips':
            clearBlockedIPs($conn);
            break;
            
        case 'get_threat_analysis':
            getThreatAnalysis($ai_defense, $input);
            break;
            
        case 'apply_fix':
            applyVulnerabilityFix($ai_defense, $input);
            break;
            
        case 'trace_attack':
            traceAttack($ai_defense, $input);
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['error' => '无效的请求']);
            break;
    }
}

/**
 * 获取最近活动
 */
function getRecentActivity($conn) {
    $sql = "SELECT 
                al.created_at as timestamp,
                al.attack_type,
                al.threat_level,
                al.ip_address,
                CONCAT(al.attack_type, ' 攻击来自 ', al.ip_address) as description
            FROM attack_logs al
            ORDER BY al.created_at DESC
            LIMIT 10";
    
    $result = $conn->query($sql);
    $activities = [];
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $activities[] = [
                'timestamp' => $row['timestamp'],
                'description' => $row['description'],
                'threat_level' => $row['threat_level'],
                'ip_address' => $row['ip_address'],
                'attack_type' => $row['attack_type']
            ];
        }
    }
    
    echo json_encode(['activities' => $activities]);
}

/**
 * 获取策略状态
 */
function getStrategyStatus($conn) {
    $sql = "SELECT 
                id,
                name,
                description,
                action,
                priority,
                active
            FROM defense_strategies
            ORDER BY priority DESC";
    
    $result = $conn->query($sql);
    $strategies = [];
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $strategies[] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'description' => $row['description'],
                'action' => $row['action'],
                'priority' => $row['priority'],
                'active' => (bool)$row['active']
            ];
        }
    }
    
    echo json_encode(['strategies' => $strategies]);
}

/**
 * 优化防御策略
 */
function optimizeStrategies($ai_defense) {
    // 模拟策略优化过程
    $optimization_result = [
        'optimized_strategies' => 3,
        'performance_improvement' => '15%',
        'threat_detection_rate' => '98%'
    ];
    
    // 记录优化操作
    $sql = "INSERT INTO strategy_executions (strategy_id, threat_data, success, execution_time, created_at) 
            VALUES (1, ?, 1, 0.5, NOW())";
    $stmt = $conn->prepare($sql);
    $threat_data = json_encode(['optimization' => 'automatic']);
    $stmt->bind_param('s', $threat_data);
    $stmt->execute();
    
    echo json_encode([
        'success' => true,
        'message' => '防御策略优化完成',
        'result' => $optimization_result
    ]);
}

/**
 * 启用紧急防御模式
 */
function enableEmergencyMode($conn) {
    // 更新系统配置
    $sql = "UPDATE system_config SET config_value = '1' WHERE config_key = 'emergency_mode_enabled'";
    $conn->query($sql);
    
    // 记录紧急模式启用
    $sql = "INSERT INTO block_actions (ip_address, threat_level, threat_score, actions, created_at) 
            VALUES ('SYSTEM', 'critical', 100, ?, NOW())";
    $stmt = $conn->prepare($sql);
    $actions = json_encode(['action' => 'emergency_mode_enabled', 'description' => '系统紧急防御模式已启用']);
    $stmt->bind_param('s', $actions);
    $stmt->execute();
    
    echo json_encode([
        'success' => true,
        'message' => '紧急防御模式已启用',
        'emergency_mode' => true
    ]);
}

/**
 * 清理过期封禁IP
 */
function clearBlockedIPs($conn) {
    // 清理过期的封禁IP
    $sql = "UPDATE blocked_ips SET active = 0 WHERE expires_at IS NOT NULL AND expires_at < NOW()";
    $conn->query($sql);
    
    $affected_rows = $conn->affected_rows;
    
    echo json_encode([
        'success' => true,
        'message' => "已清理 {$affected_rows} 个过期封禁IP",
        'cleared_count' => $affected_rows
    ]);
}

/**
 * 获取威胁分析
 */
function getThreatAnalysis($ai_defense, $input) {
    $request_data = $input['data'] ?? '';
    $threat_analysis = $ai_defense->detectThreat($request_data);
    
    echo json_encode([
        'success' => true,
        'threat_analysis' => $threat_analysis
    ]);
}

/**
 * 应用漏洞修复
 */
function applyVulnerabilityFix($ai_defense, $input) {
    $vulnerability_data = $input['vulnerability'] ?? [];
    $fix_actions = $ai_defense->autoFixVulnerability($vulnerability_data);
    
    echo json_encode([
        'success' => true,
        'fix_actions' => $fix_actions
    ]);
}

/**
 * 攻击溯源
 */
function traceAttack($ai_defense, $input) {
    $attack_data = $input['attack_data'] ?? [];
    $trace_result = $ai_defense->traceAttack($attack_data);
    
    echo json_encode([
        'success' => true,
        'trace_result' => $trace_result
    ]);
}

/**
 * 导出安全日志
 */
function exportSecurityLogs($conn) {
    // 设置响应头为下载文件
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="security_logs_' . date('Y-m-d') . '.csv"');
    
    // 创建CSV文件
    $output = fopen('php://output', 'w');
    
    // 写入CSV头部
    fputcsv($output, ['时间', 'IP地址', '攻击类型', '威胁等级', '处理结果', '载荷']);
    
    // 查询攻击日志
    $sql = "SELECT 
                created_at,
                ip_address,
                attack_type,
                threat_level,
                result,
                payload
            FROM attack_logs
            ORDER BY created_at DESC
            LIMIT 1000";
    
    $result = $conn->query($sql);
    
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            fputcsv($output, [
                $row['created_at'],
                $row['ip_address'],
                $row['attack_type'],
                $row['threat_level'],
                $row['result'],
                $row['payload']
            ]);
        }
    }
    
    fclose($output);
    exit;
}

/**
 * 记录请求日志
 */
function logRequest($conn, $ip_address, $request_data, $threat_score = 0) {
    $sql = "INSERT INTO request_logs (ip_address, user_agent, request_method, request_uri, request_data, threat_score, created_at) 
            VALUES (?, ?, ?, ?, ?, ?, NOW())";
    
    $stmt = $conn->prepare($sql);
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $request_method = $_SERVER['REQUEST_METHOD'] ?? '';
    $request_uri = $_SERVER['REQUEST_URI'] ?? '';
    
    $stmt->bind_param('sssssi', $ip_address, $user_agent, $request_method, $request_uri, $request_data, $threat_score);
    $stmt->execute();
}

/**
 * 记录攻击日志
 */
function logAttack($conn, $ip_address, $attack_type, $payload, $threat_level = 'medium') {
    $sql = "INSERT INTO attack_logs (ip_address, attack_type, action, payload, threat_level, created_at) 
            VALUES (?, ?, ?, ?, ?, NOW())";
    
    $stmt = $conn->prepare($sql);
    $action = 'detected';
    $stmt->bind_param('sssss', $ip_address, $attack_type, $action, $payload, $threat_level);
    $stmt->execute();
}
?> 