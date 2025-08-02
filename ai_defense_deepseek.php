<?php
/**
 * AI自适应防御决策系统 - DeepSeek AI集成版本
 * 使用DeepSeek AI进行威胁检测和决策
 */

class DeepSeekAIDefense {
    private $api_key;
    private $api_url = 'https://api.deepseek.com/v1/chat/completions';
    private $conn;
    
    public function __construct($conn, $api_key = null) {
        $this->conn = $conn;
        // 优先使用传入的API密钥，其次使用配置文件中的密钥
        $this->api_key = $api_key ?? (defined('DEEPSEEK_API_KEY') ? DEEPSEEK_API_KEY : getenv('DEEPSEEK_API_KEY'));
    }
    
    /**
     * 使用DeepSeek AI检测威胁
     */
    public function detectThreatWithAI($request_data) {
        $prompt = $this->buildThreatDetectionPrompt($request_data);
        
        $response = $this->callDeepSeekAPI($prompt);
        
        return $this->parseAIResponse($response);
    }
    
    /**
     * 使用DeepSeek AI优化防御策略
     */
    public function optimizeStrategyWithAI($threat_analysis) {
        $prompt = $this->buildStrategyOptimizationPrompt($threat_analysis);
        
        $response = $this->callDeepSeekAPI($prompt);
        
        return $this->parseStrategyResponse($response);
    }
    
    /**
     * 使用DeepSeek AI进行攻击溯源
     */
    public function traceAttackWithAI($attack_data) {
        $prompt = $this->buildAttackTracePrompt($attack_data);
        
        $response = $this->callDeepSeekAPI($prompt);
        
        return $this->parseTraceResponse($response);
    }
    
    /**
     * 使用DeepSeek AI生成漏洞修复建议
     */
    public function generateFixWithAI($vulnerability_data) {
        $prompt = $this->buildFixGenerationPrompt($vulnerability_data);
        
        $response = $this->callDeepSeekAPI($prompt);
        
        return $this->parseFixResponse($response);
    }
    
    /**
     * 构建威胁检测提示词
     */
    private function buildThreatDetectionPrompt($request_data) {
        return "你是一个网络安全专家。请分析以下HTTP请求数据，判断是否存在安全威胁：

请求数据：{$request_data}

请从以下角度进行分析：
1. SQL注入攻击
2. XSS跨站脚本攻击
3. 文件包含攻击
4. 命令注入攻击
5. 路径遍历攻击
6. CSRF攻击
7. 其他可疑行为

请以JSON格式返回分析结果，包含以下字段：
{
    \"threat_level\": \"low/medium/high/critical\",
    \"threat_score\": 0-100,
    \"detected_threats\": [\"威胁类型列表\"],
    \"confidence\": 0.0-1.0,
    \"reasoning\": \"分析推理过程\",
    \"recommendations\": [\"建议措施列表\"]
}";
    }
    
    /**
     * 构建策略优化提示词
     */
    private function buildStrategyOptimizationPrompt($threat_analysis) {
        return "你是一个网络安全防御策略专家。基于以下威胁分析结果，请推荐最优的防御策略：

威胁分析：{$threat_analysis}

请考虑以下防御策略：
1. 实时阻断
2. 速率限制
3. IP封禁
4. 增加监控
5. 紧急模式
6. 通知管理员
7. 日志记录

请以JSON格式返回优化策略，包含以下字段：
{
    \"optimized_strategies\": [
        {
            \"name\": \"策略名称\",
            \"action\": \"具体动作\",
            \"effectiveness\": 0.0-1.0,
            \"priority\": 1-10,
            \"description\": \"策略描述\"
        }
    ],
    \"optimization_reasoning\": \"优化推理过程\"
}";
    }
    
    /**
     * 构建攻击溯源提示词
     */
    private function buildAttackTracePrompt($attack_data) {
        return "你是一个网络安全取证专家。请分析以下攻击数据，进行深度溯源：

攻击数据：{$attack_data}

请从以下角度进行分析：
1. 攻击源分析
2. 攻击链重建
3. 攻击工具识别
4. 攻击者画像
5. 威胁情报关联

请以JSON格式返回溯源结果，包含以下字段：
{
    \"attack_chain\": [\"攻击步骤列表\"],
    \"source_analysis\": {
        \"ip_geolocation\": \"地理位置\",
        \"attack_pattern\": \"攻击模式\",
        \"threat_intelligence\": \"威胁情报\"
    },
    \"recommendations\": [\"建议措施列表\"],
    \"confidence\": 0.0-1.0
}";
    }
    
    /**
     * 构建修复建议提示词
     */
    private function buildFixGenerationPrompt($vulnerability_data) {
        return "你是一个安全代码专家。请为以下漏洞生成具体的修复建议：

漏洞信息：{$vulnerability_data}

请提供：
1. 漏洞类型识别
2. 具体修复代码
3. 安全最佳实践
4. 验证方法

请以JSON格式返回修复建议，包含以下字段：
{
    \"vulnerability_type\": \"漏洞类型\",
    \"fix_actions\": [
        {
            \"action\": \"修复动作\",
            \"description\": \"详细描述\",
            \"code_example\": \"代码示例\"
        }
    ],
    \"security_best_practices\": [\"最佳实践列表\"],
    \"verification_methods\": [\"验证方法列表\"]
}";
    }
    
    /**
     * 调用DeepSeek API
     */
    private function callDeepSeekAPI($prompt) {
        if (!$this->api_key) {
            throw new Exception('DeepSeek API密钥未设置');
        }
        
        $data = [
            'model' => 'deepseek-chat',
            'messages' => [
                [
                    'role' => 'system',
                    'content' => '你是一个专业的网络安全AI助手，专门负责威胁检测、防御策略优化、攻击溯源和漏洞修复。请严格按照要求的JSON格式返回结果。'
                ],
                [
                    'role' => 'user',
                    'content' => $prompt
                ]
            ],
            'temperature' => defined('DEEPSEEK_TEMPERATURE') ? DEEPSEEK_TEMPERATURE : 0.1,
            'max_tokens' => defined('DEEPSEEK_MAX_TOKENS') ? DEEPSEEK_MAX_TOKENS : 2000
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->api_url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Authorization: Bearer ' . $this->api_key
        ]);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, defined('DEEPSEEK_TIMEOUT') ? DEEPSEEK_TIMEOUT : 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($http_code !== 200) {
            throw new Exception('DeepSeek API调用失败: ' . $http_code);
        }
        
        $result = json_decode($response, true);
        
        if (!isset($result['choices'][0]['message']['content'])) {
            throw new Exception('DeepSeek API响应格式错误');
        }
        
        return $result['choices'][0]['message']['content'];
    }
    
    /**
     * 解析AI威胁检测响应
     */
    private function parseAIResponse($response) {
        // 尝试提取JSON部分
        $json_start = strpos($response, '{');
        $json_end = strrpos($response, '}');
        
        if ($json_start !== false && $json_end !== false) {
            $json_str = substr($response, $json_start, $json_end - $json_start + 1);
            $parsed = json_decode($json_str, true);
            
            if ($parsed) {
                return [
                    'threat_level' => $parsed['threat_level'] ?? 'low',
                    'threat_score' => $parsed['threat_score'] ?? 0,
                    'detected_threats' => $parsed['detected_threats'] ?? [],
                    'confidence' => $parsed['confidence'] ?? 0.5,
                    'reasoning' => $parsed['reasoning'] ?? '',
                    'recommendations' => $parsed['recommendations'] ?? [],
                    'ai_response' => $response
                ];
            }
        }
        
        // 如果JSON解析失败，使用传统方法
        return $this->fallbackThreatDetection($response);
    }
    
    /**
     * 解析策略优化响应
     */
    private function parseStrategyResponse($response) {
        $json_start = strpos($response, '{');
        $json_end = strrpos($response, '}');
        
        if ($json_start !== false && $json_end !== false) {
            $json_str = substr($response, $json_start, $json_end - $json_start + 1);
            $parsed = json_decode($json_str, true);
            
            if ($parsed) {
                return [
                    'optimized_strategies' => $parsed['optimized_strategies'] ?? [],
                    'optimization_reasoning' => $parsed['optimization_reasoning'] ?? '',
                    'ai_response' => $response
                ];
            }
        }
        
        return [
            'optimized_strategies' => [],
            'optimization_reasoning' => 'AI响应解析失败',
            'ai_response' => $response
        ];
    }
    
    /**
     * 解析攻击溯源响应
     */
    private function parseTraceResponse($response) {
        $json_start = strpos($response, '{');
        $json_end = strrpos($response, '}');
        
        if ($json_start !== false && $json_end !== false) {
            $json_str = substr($response, $json_start, $json_end - $json_start + 1);
            $parsed = json_decode($json_str, true);
            
            if ($parsed) {
                return [
                    'attack_chain' => $parsed['attack_chain'] ?? [],
                    'source_analysis' => $parsed['source_analysis'] ?? [],
                    'recommendations' => $parsed['recommendations'] ?? [],
                    'confidence' => $parsed['confidence'] ?? 0.5,
                    'ai_response' => $response
                ];
            }
        }
        
        return [
            'attack_chain' => [],
            'source_analysis' => [],
            'recommendations' => [],
            'confidence' => 0.0,
            'ai_response' => $response
        ];
    }
    
    /**
     * 解析修复建议响应
     */
    private function parseFixResponse($response) {
        $json_start = strpos($response, '{');
        $json_end = strrpos($response, '}');
        
        if ($json_start !== false && $json_end !== false) {
            $json_str = substr($response, $json_start, $json_end - $json_start + 1);
            $parsed = json_decode($json_str, true);
            
            if ($parsed) {
                return [
                    'vulnerability_type' => $parsed['vulnerability_type'] ?? '',
                    'fix_actions' => $parsed['fix_actions'] ?? [],
                    'security_best_practices' => $parsed['security_best_practices'] ?? [],
                    'verification_methods' => $parsed['verification_methods'] ?? [],
                    'ai_response' => $response
                ];
            }
        }
        
        return [
            'vulnerability_type' => '',
            'fix_actions' => [],
            'security_best_practices' => [],
            'verification_methods' => [],
            'ai_response' => $response
        ];
    }
    
    /**
     * 备用威胁检测方法
     */
    private function fallbackThreatDetection($response) {
        // 简单的关键词检测
        $threat_score = 0;
        $detected_threats = [];
        
        $threat_patterns = [
            'sql_injection' => ['/.*[\'\"].*[=<>].*/', '/.*UNION.*SELECT.*/', '/.*DROP.*TABLE.*/'],
            'xss' => ['/<script.*>/i', '/javascript:/i', '/on\w+\s*=/i'],
            'file_inclusion' => ['/.*\.\./.*', '/.*php:\/\/.*/', '/.*data:\/\/.*/'],
            'command_injection' => ['/.*[;&|`].*[a-z]+.*/', '/.*\$\{.*\}.*/']
        ];
        
        foreach ($threat_patterns as $type => $patterns) {
            foreach ($patterns as $pattern) {
                if (preg_match($pattern, $response)) {
                    $threat_score += 20;
                    $detected_threats[] = $type;
                    break;
                }
            }
        }
        
        return [
            'threat_level' => $threat_score >= 80 ? 'critical' : ($threat_score >= 60 ? 'high' : ($threat_score >= 40 ? 'medium' : 'low')),
            'threat_score' => $threat_score,
            'detected_threats' => $detected_threats,
            'confidence' => 0.3,
            'reasoning' => '使用备用检测方法',
            'recommendations' => ['启用AI检测', '更新威胁情报'],
            'ai_response' => $response
        ];
    }
    
    /**
     * 设置API密钥
     */
    public function setApiKey($api_key) {
        $this->api_key = $api_key;
    }
    
    /**
     * 测试API连接
     */
    public function testConnection() {
        try {
            $test_prompt = "请简单回复'连接成功'";
            $response = $this->callDeepSeekAPI($test_prompt);
            return ['success' => true, 'message' => 'DeepSeek API连接成功'];
        } catch (Exception $e) {
            return ['success' => false, 'message' => 'DeepSeek API连接失败: ' . $e->getMessage()];
        }
    }
}

// 使用示例
if (basename($_SERVER['SCRIPT_NAME']) === 'ai_defense_deepseek.php') {
    require_once 'db.php';
    
    $deepseek_defense = new DeepSeekAIDefense($conn);
    
    // 设置API密钥（请替换为您的实际密钥）
    // $deepseek_defense->setApiKey('your_deepseek_api_key_here');
    
    // 测试连接
    $test_result = $deepseek_defense->testConnection();
    echo json_encode($test_result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
}
?> 