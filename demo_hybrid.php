<?php
/**
 * 混合模式AI防御系统演示页面
 * 优先使用DeepSeek AI，失败时自动切换到传统方法
 * 管理员专用
 */

// 关闭错误输出
error_reporting(0);
ini_set('display_errors', 0);

require_once 'admin_check.php';
require_once 'db.php';
require_once 'deepseek_config.php';
require_once 'ai_defense_deepseek.php';
require_once 'ai_defense_system.php';

$deepseek_defense = new DeepSeekAIDefense($conn);
$traditional_defense = new AIDefenseSystem($conn);
$message = '';
$result = null;
$ai_response = '';
$detection_mode = '';

// 处理表单提交
if ($_POST) {
    $input_data = $_POST['test_input'] ?? '';
    $api_key = $_POST['api_key'] ?? '';
    
    if ($input_data) {
        // 设置API密钥
        if ($api_key) {
            $deepseek_defense->setApiKey($api_key);
        } else {
            $deepseek_defense->setApiKey(DEEPSEEK_API_KEY);
        }
        
        // 首先尝试使用DeepSeek AI
        try {
            $threat_analysis = $deepseek_defense->detectThreatWithAI($input_data);
            $result = $threat_analysis;
            $ai_response = $threat_analysis['ai_response'] ?? '';
            $detection_mode = 'DeepSeek AI';
            
            // 根据威胁等级显示不同消息
            switch ($threat_analysis['threat_level']) {
                case 'critical':
                    $message = '🚨 AI检测到严重威胁！';
                    $message_class = 'danger';
                    break;
                case 'high':
                    $message = '⚠️ AI检测到高风险威胁！';
                    $message_class = 'warning';
                    break;
                case 'medium':
                    $message = '🔍 AI检测到中等风险威胁！';
                    $message_class = 'info';
                    break;
                default:
                    $message = '✅ AI未检测到威胁！';
                    $message_class = 'success';
            }
        } catch (Exception $e) {
            // AI检测失败，切换到传统方法
            try {
                $threat_analysis = $traditional_defense->detectThreat($input_data);
                $result = $threat_analysis;
                $detection_mode = '传统方法（AI不可用）';
                
                switch ($threat_analysis['threat_level']) {
                    case 'critical':
                        $message = '🚨 传统方法检测到严重威胁！';
                        $message_class = 'danger';
                        break;
                    case 'high':
                        $message = '⚠️ 传统方法检测到高风险威胁！';
                        $message_class = 'warning';
                        break;
                    case 'medium':
                        $message = '🔍 传统方法检测到中等风险威胁！';
                        $message_class = 'info';
                        break;
                    default:
                        $message = '✅ 传统方法未检测到威胁！';
                        $message_class = 'success';
                }
            } catch (Exception $e2) {
                $message = '❌ 所有检测方法都失败了: ' . $e2->getMessage();
                $message_class = 'danger';
            }
        }
    }
}

// 测试API连接
$connection_test = $deepseek_defense->testConnection();
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>混合模式AI防御系统演示</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .container {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
        }
        
        h1 {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        
        input[type="text"], textarea {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 5px;
            background: rgba(255,255,255,0.9);
            color: #333;
        }
        
        button {
            background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 16px;
            margin: 10px 5px;
        }
        
        button:hover {
            opacity: 0.9;
        }
        
        .message {
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
            font-weight: bold;
        }
        
        .message.success { background: rgba(46, 213, 115, 0.8); }
        .message.info { background: rgba(54, 123, 245, 0.8); }
        .message.warning { background: rgba(255, 165, 2, 0.8); }
        .message.danger { background: rgba(255, 71, 87, 0.8); }
        
        .result-box {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .ai-response {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }
        
        .examples {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .example-item {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            cursor: pointer;
        }
        
        .example-item:hover {
            background: rgba(255,255,255,0.2);
        }
        
        .connection-status {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        
        .feature-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        
        .feature-item {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }
        
        .feature-icon {
            font-size: 48px;
            margin-bottom: 10px;
        }
        
        .mode-indicator {
            background: rgba(255,255,255,0.1);
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            text-align: center;
            font-weight: bold;
        }
        
        .mode-ai { background: rgba(46, 213, 115, 0.3); }
        .mode-traditional { background: rgba(255, 165, 2, 0.3); }
        
        .nav-bar {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }
        
        .nav-btn {
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            padding: 10px 15px;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-size: 14px;
            font-weight: 500;
        }
        
        .nav-btn:hover {
            background: rgba(255,255,255,0.3);
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- 导航栏 -->
        <div class="nav-bar">
            <a href="admin_ai_defense.php" class="nav-btn">← 返回AI防御系统</a>
            <a href="demo_deepseek.php" class="nav-btn">🤖 纯AI模式</a>
            <a href="demo.php" class="nav-btn">🛡️ 传统模式</a>
        </div>
        
        <h1>🔄 混合模式AI自适应防御决策系统</h1>
        
        <!-- 连接状态 -->
        <div class="connection-status">
            <h3>🔗 API连接状态</h3>
            <p><strong>DeepSeek API：</strong> 
                <?php if ($connection_test['success']): ?>
                    <span style="color: #2ed573;">✅ 已连接</span>
                <?php else: ?>
                    <span style="color: #ff4757;">❌ 未连接</span>
                <?php endif; ?>
            </p>
            <p><strong>消息：</strong> <?php echo $connection_test['message']; ?></p>
            <p><strong>传统方法：</strong> <span style="color: #2ed573;">✅ 可用</span></p>
        </div>
        
        <!-- 检测模式说明 -->
        <div class="feature-grid">
            <div class="feature-item">
                <div class="feature-icon">🤖</div>
                <h4>DeepSeek AI模式</h4>
                <p>优先使用AI进行智能威胁检测，准确率更高</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🛡️</div>
                <h4>传统方法模式</h4>
                <p>基于规则和模式匹配，稳定可靠</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🔄</div>
                <h4>自动切换</h4>
                <p>AI不可用时自动切换到传统方法</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">⚡</div>
                <h4>实时检测</h4>
                <p>无论使用哪种模式都能实时检测威胁</p>
            </div>
        </div>
        
        <!-- 威胁检测表单 -->
        <form method="POST">
            <div class="form-group">
                <label for="api_key">DeepSeek API密钥（可选）：</label>
                <input type="text" name="api_key" id="api_key" placeholder="留空将使用配置文件中的密钥" value="<?php echo $_POST['api_key'] ?? ''; ?>">
                <small style="color: #ccc;">当前配置的密钥：sk-0ffdfe2bef9f4f93a5b0416bd272fc42</small>
            </div>
            
            <div class="form-group">
                <label for="test_input">输入要检测的内容：</label>
                <textarea name="test_input" id="test_input" rows="4" placeholder="例如：username=admin' OR 1=1--&password=test"><?php echo $_POST['test_input'] ?? ''; ?></textarea>
            </div>
            
            <button type="submit">🔍 检测威胁</button>
            <button type="button" onclick="clearForm()">🗑️ 清空</button>
        </form>
        
        <!-- 检测结果 -->
        <?php if ($message): ?>
        <div class="message <?php echo $message_class; ?>">
            <?php echo $message; ?>
        </div>
        
        <!-- 检测模式指示器 -->
        <div class="mode-indicator <?php echo $detection_mode === 'DeepSeek AI' ? 'mode-ai' : 'mode-traditional'; ?>">
            🔄 当前检测模式：<?php echo $detection_mode; ?>
        </div>
        
        <div class="result-box">
            <h3>🔍 检测结果详情：</h3>
            <p><strong>威胁等级：</strong> <?php echo strtoupper($result['threat_level']); ?></p>
            <p><strong>威胁评分：</strong> <?php echo $result['threat_score']; ?>/100</p>
            <p><strong>置信度：</strong> <?php echo round($result['confidence'] * 100, 1); ?>%</p>
            <p><strong>客户端IP：</strong> <?php echo $result['client_ip']; ?></p>
            <?php if (!empty($result['detected_threats'])): ?>
            <p><strong>检测到的威胁：</strong> <?php echo implode(', ', $result['detected_threats']); ?></p>
            <?php endif; ?>
            <?php if (!empty($result['reasoning'])): ?>
            <p><strong>分析推理：</strong> <?php echo $result['reasoning']; ?></p>
            <?php endif; ?>
            <?php if (!empty($result['recommendations'])): ?>
            <p><strong>建议措施：</strong></p>
            <ul>
                <?php foreach ($result['recommendations'] as $rec): ?>
                <li><?php echo htmlspecialchars($rec); ?></li>
                <?php endforeach; ?>
            </ul>
            <?php endif; ?>
        </div>
        
        <!-- AI原始响应 -->
        <?php if ($ai_response): ?>
        <div class="result-box">
            <h3>🤖 AI原始响应：</h3>
            <div class="ai-response"><?php echo htmlspecialchars($ai_response); ?></div>
        </div>
        <?php endif; ?>
        <?php endif; ?>
        
        <!-- 测试示例 -->
        <div class="examples">
            <h3>💡 测试示例（点击使用）：</h3>
            <div class="example-item" onclick="useExample('username=admin&password=123456')">
                ✅ 正常输入：username=admin&password=123456
            </div>
            <div class="example-item" onclick="useExample('username=admin\' OR 1=1--&password=test')">
                🚨 SQL注入：username=admin' OR 1=1--&password=test
            </div>
            <div class="example-item" onclick="useExample('<script>alert(\'XSS\')</script>')">
                ⚠️ XSS攻击：&lt;script&gt;alert('XSS')&lt;/script&gt;
            </div>
            <div class="example-item" onclick="useExample('../../../etc/passwd')">
                🔍 路径遍历：../../../etc/passwd
            </div>
            <div class="example-item" onclick="useExample('; ls -la; echo')">
                💀 命令注入：; ls -la; echo
            </div>
            <div class="example-item" onclick="useExample('<?php echo '<?php system($_GET[\'cmd\']); ?>'; ?>')">
                🐛 PHP代码注入：&lt;?php system($_GET['cmd']); ?&gt;
            </div>
        </div>
        
        <!-- 使用说明 -->
        <div class="examples">
            <h3>📖 混合模式使用说明：</h3>
            <p>1. <strong>自动模式</strong>：系统会优先尝试使用DeepSeek AI，如果失败会自动切换到传统方法</p>
            <p>2. <strong>AI模式</strong>：提供更准确的威胁检测和智能分析</p>
            <p>3. <strong>传统模式</strong>：基于规则和模式匹配，稳定可靠</p>
            <p>4. <strong>无缝切换</strong>：用户无需手动选择，系统自动处理</p>
            
            <h4>代码集成示例：</h4>
            <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; overflow-x: auto;">
// 混合模式集成
require_once 'ai_defense_deepseek.php';
require_once 'ai_defense_system.php';

$deepseek_defense = new DeepSeekAIDefense($conn);
$traditional_defense = new AIDefenseSystem($conn);

// 尝试AI检测，失败时使用传统方法
try {
    $threat_analysis = $deepseek_defense->detectThreatWithAI($request_data);
    $detection_mode = 'AI';
} catch (Exception $e) {
    $threat_analysis = $traditional_defense->detectThreat($request_data);
    $detection_mode = 'Traditional';
}</pre>
        </div>
        
        <!-- 模式对比 -->
        <div class="examples">
            <h3>🔄 检测模式对比：</h3>
            <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
                <tr style="background: rgba(255,255,255,0.1);">
                    <th style="padding: 10px; text-align: left;">特性</th>
                    <th style="padding: 10px; text-align: left;">DeepSeek AI</th>
                    <th style="padding: 10px; text-align: left;">传统方法</th>
                </tr>
                <tr>
                    <td style="padding: 10px;">检测准确率</td>
                    <td style="padding: 10px;">90-95%</td>
                    <td style="padding: 10px;">70-80%</td>
                </tr>
                <tr style="background: rgba(255,255,255,0.05);">
                    <td style="padding: 10px;">响应速度</td>
                    <td style="padding: 10px;">1-3秒</td>
                    <td style="padding: 10px;">&lt;1秒</td>
                </tr>
                <tr>
                    <td style="padding: 10px;">依赖网络</td>
                    <td style="padding: 10px;">是</td>
                    <td style="padding: 10px;">否</td>
                </tr>
                <tr style="background: rgba(255,255,255,0.05);">
                    <td style="padding: 10px;">成本</td>
                    <td style="padding: 10px;">API费用</td>
                    <td style="padding: 10px;">免费</td>
                </tr>
                <tr>
                    <td style="padding: 10px;">智能分析</td>
                    <td style="padding: 10px;">✅ 支持</td>
                    <td style="padding: 10px;">❌ 有限</td>
                </tr>
            </table>
        </div>
        
        <!-- 相关链接 -->
        <div class="examples">
            <h3>🔗 相关链接：</h3>
            <p><a href="demo_deepseek.php" style="color: #48dbfb;">→ 纯AI模式演示</a></p>
            <p><a href="demo.php" style="color: #48dbfb;">→ 纯传统模式演示</a></p>
            <p><a href="ai_defense_dashboard.php" style="color: #48dbfb;">→ 系统管理面板</a></p>
        </div>
    </div>

    <script>
        function useExample(text) {
            document.getElementById('test_input').value = text;
        }
        
        function clearForm() {
            document.getElementById('test_input').value = '';
            document.getElementById('api_key').value = '';
        }
    </script>
</body>
</html> 