<?php
/**
 * DeepSeek AI配置文件
 * 请妥善保管您的API密钥，不要泄露给他人
 */

// DeepSeek API配置
define('DEEPSEEK_API_KEY', 'sk-0ffdfe2bef9f4f93a5b0416bd272fc42');
define('DEEPSEEK_API_URL', 'https://api.deepseek.com/v1/chat/completions');

// 安全设置
define('DEEPSEEK_TIMEOUT', 30); // API请求超时时间（秒）
define('DEEPSEEK_MAX_TOKENS', 2000); // 最大token数
define('DEEPSEEK_TEMPERATURE', 0.1); // 响应随机性（0-1，越低越确定）

// 日志设置
define('DEEPSEEK_LOG_ENABLED', true);
define('DEEPSEEK_LOG_FILE', 'ai_defense_logs/deepseek_api.log');

/**
 * 记录DeepSeek API调用日志
 */
function logDeepSeekAPI($action, $request_data, $response_data, $success = true) {
    if (!DEEPSEEK_LOG_ENABLED) return;
    
    $log_dir = dirname(DEEPSEEK_LOG_FILE);
    if (!is_dir($log_dir)) {
        mkdir($log_dir, 0755, true);
    }
    
    $log_entry = [
        'timestamp' => date('Y-m-d H:i:s'),
        'action' => $action,
        'success' => $success,
        'request' => $request_data,
        'response' => $response_data
    ];
    
    file_put_contents(DEEPSEEK_LOG_FILE, json_encode($log_entry, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND | LOCK_EX);
}

/**
 * 获取DeepSeek API密钥
 */
function getDeepSeekAPIKey() {
    return DEEPSEEK_API_KEY;
}

/**
 * 验证API密钥格式
 */
function validateDeepSeekAPIKey($api_key) {
    return preg_match('/^sk-[a-zA-Z0-9]{32}$/', $api_key);
}

// 验证当前配置的API密钥
if (!validateDeepSeekAPIKey(DEEPSEEK_API_KEY)) {
    error_log('警告：DeepSeek API密钥格式可能不正确');
}
?> 