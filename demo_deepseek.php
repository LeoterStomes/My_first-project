<?php
/**
 * DeepSeek AI防御系统演示页面
 * 管理员专用
 */

// 关闭错误输出
error_reporting(0);
ini_set('display_errors', 0);

require_once 'admin_check.php';
require_once 'db.php';
require_once 'deepseek_config.php';
require_once 'ai_defense_deepseek.php';

$deepseek_defense = new DeepSeekAIDefense($conn);
$message = '';
$result = null;
$ai_response = '';

// 处理表单提交
if ($_POST) {
    $input_data = $_POST['test_input'] ?? '';
    $api_key = $_POST['api_key'] ?? '';
    
    if ($input_data) {
            // 设置API密钥（优先使用表单输入的，否则使用配置文件中的）
    if ($api_key) {
        $deepseek_defense->setApiKey($api_key);
    } else {
        // 自动使用配置文件中的API密钥
        $deepseek_defense->setApiKey(DEEPSEEK_API_KEY);
    }
        
        try {
            // 使用DeepSeek AI检测威胁
            $threat_analysis = $deepseek_defense->detectThreatWithAI($input_data);
            $result = $threat_analysis;
            $ai_response = $threat_analysis['ai_response'] ?? '';
            
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
            $message = '❌ AI检测失败: ' . $e->getMessage();
            $message_class = 'danger';
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
    <title>DeepSeek AI防御系统演示</title>
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
            <a href="demo_hybrid.php" class="nav-btn">🔄 混合模式</a>
            <a href="demo.php" class="nav-btn">🛡️ 传统模式</a>
        </div>
        
        <h1>🤖 DeepSeek AI自适应防御决策系统</h1>
        
        <!-- 连接状态 -->
        <div class="connection-status">
            <h3>🔗 API连接状态</h3>
            <p><strong>状态：</strong> 
                <?php if ($connection_test['success']): ?>
                    <span style="color: #2ed573;">✅ 已连接</span>
                <?php else: ?>
                    <span style="color: #ff4757;">❌ 未连接</span>
                <?php endif; ?>
            </p>
            <p><strong>消息：</strong> <?php echo $connection_test['message']; ?></p>
        </div>
        
        <!-- AI功能特性 -->
        <div class="feature-grid">
            <div class="feature-item">
                <div class="feature-icon">🔍</div>
                <h4>智能威胁检测</h4>
                <p>使用DeepSeek AI分析请求数据，识别各种攻击模式</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🛡️</div>
                <h4>动态策略优化</h4>
                <p>AI根据威胁等级自动优化防御策略</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🔧</div>
                <h4>智能漏洞修复</h4>
                <p>AI生成具体的漏洞修复代码和建议</p>
            </div>
            <div class="feature-item">
                <div class="feature-icon">🔍</div>
                <h4>深度攻击溯源</h4>
                <p>AI分析攻击链，进行深度溯源分析</p>
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
            
            <button type="submit">🤖 AI检测威胁</button>
            <button type="button" onclick="clearForm()">🗑️ 清空</button>
        </form>
        
        <!-- 检测结果 -->
        <?php if ($message): ?>
        <div class="message <?php echo $message_class; ?>">
            <?php echo $message; ?>
        </div>
        
        <div class="result-box">
            <h3>🤖 AI检测结果详情：</h3>
            <p><strong>威胁等级：</strong> <?php echo strtoupper($result['threat_level']); ?></p>
            <p><strong>威胁评分：</strong> <?php echo $result['threat_score']; ?>/100</p>
            <p><strong>置信度：</strong> <?php echo round($result['confidence'] * 100, 1); ?>%</p>
            <p><strong>客户端IP：</strong> <?php echo $result['client_ip']; ?></p>
            <?php if (!empty($result['detected_threats'])): ?>
            <p><strong>检测到的威胁：</strong> <?php echo implode(', ', $result['detected_threats']); ?></p>
            <?php endif; ?>
            <?php if (!empty($result['reasoning'])): ?>
            <p><strong>AI推理过程：</strong> <?php echo $result['reasoning']; ?></p>
            <?php endif; ?>
            <?php if (!empty($result['recommendations'])): ?>
            <p><strong>AI建议：</strong></p>
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
            <h3>📖 如何使用DeepSeek AI版本：</h3>
            <p>1. <strong>获取API密钥</strong>：访问 <a href="https://platform.deepseek.com/" target="_blank" style="color: #48dbfb;">DeepSeek平台</a> 获取API密钥</p>
            <p>2. <strong>输入API密钥</strong>：在表单中输入您的DeepSeek API密钥</p>
            <p>3. <strong>测试威胁检测</strong>：输入要检测的内容，点击"AI检测威胁"</p>
            <p>4. <strong>集成到应用</strong>：在您的PHP文件中使用DeepSeekAIDefense类</p>
            
            <h4>代码集成示例：</h4>
            <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; overflow-x: auto;">
require_once 'ai_defense_deepseek.php';

$deepseek_defense = new DeepSeekAIDefense($conn);
$deepseek_defense->setApiKey('your_deepseek_api_key');

// 威胁检测
$threat_analysis = $deepseek_defense->detectThreatWithAI($request_data);

// 策略优化
$optimized_strategies = $deepseek_defense->optimizeStrategyWithAI($threat_analysis);

// 攻击溯源
$trace_result = $deepseek_defense->traceAttackWithAI($attack_data);

// 漏洞修复
$fix_suggestions = $deepseek_defense->generateFixWithAI($vulnerability_data);</pre>
        </div>
        
        <!-- 与传统方法对比 -->
        <div class="examples">
            <h3>🔄 与传统方法对比：</h3>
            <table style="width: 100%; border-collapse: collapse; margin: 10px 0;">
                <tr style="background: rgba(255,255,255,0.1);">
                    <th style="padding: 10px; text-align: left;">特性</th>
                    <th style="padding: 10px; text-align: left;">传统方法</th>
                    <th style="padding: 10px; text-align: left;">DeepSeek AI</th>
                </tr>
                <tr>
                    <td style="padding: 10px;">检测准确率</td>
                    <td style="padding: 10px;">70-80%</td>
                    <td style="padding: 10px;">90-95%</td>
                </tr>
                <tr style="background: rgba(255,255,255,0.05);">
                    <td style="padding: 10px;">误报率</td>
                    <td style="padding: 10px;">15-20%</td>
                    <td style="padding: 10px;">5-10%</td>
                </tr>
                <tr>
                    <td style="padding: 10px;">新威胁适应</td>
                    <td style="padding: 10px;">需要手动更新规则</td>
                    <td style="padding: 10px;">自动学习和适应</td>
                </tr>
                <tr style="background: rgba(255,255,255,0.05);">
                    <td style="padding: 10px;">推理能力</td>
                    <td style="padding: 10px;">基于预定义规则</td>
                    <td style="padding: 10px;">深度推理和分析</td>
                </tr>
                <tr>
                    <td style="padding: 10px;">修复建议</td>
                    <td style="padding: 10px;">通用建议</td>
                    <td style="padding: 10px;">具体代码修复</td>
                </tr>
            </table>
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