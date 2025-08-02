<?php
/**
 * AI防御系统演示页面
 * 展示如何使用AI防御系统检测威胁
 * 管理员专用
 */

// 关闭错误输出
error_reporting(0);
ini_set('display_errors', 0);

require_once 'admin_check.php';
require_once 'db.php';
require_once 'ai_defense_system.php';

$ai_defense = new AIDefenseSystem($conn);
$message = '';
$result = null;

// 处理表单提交
if ($_POST) {
    $input_data = $_POST['test_input'] ?? '';
    
    if ($input_data) {
        // 使用AI防御系统检测威胁
        $threat_analysis = $ai_defense->detectThreat($input_data);
        $result = $threat_analysis;
        
        // 根据威胁等级显示不同消息
        switch ($threat_analysis['threat_level']) {
            case 'critical':
                $message = '🚨 检测到严重威胁！';
                $message_class = 'danger';
                break;
            case 'high':
                $message = '⚠️ 检测到高风险威胁！';
                $message_class = 'warning';
                break;
            case 'medium':
                $message = '🔍 检测到中等风险威胁！';
                $message_class = 'info';
                break;
            default:
                $message = '✅ 未检测到威胁！';
                $message_class = 'success';
        }
    }
}

// 获取系统状态
$system_status = $ai_defense->getSystemStatus();
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI防御系统演示</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
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
        
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        
        .status-item {
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 10px;
            text-align: center;
        }
        
        .status-value {
            font-size: 24px;
            font-weight: bold;
            margin: 5px 0;
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
            <a href="demo_hybrid.php" class="nav-btn">🔄 混合模式</a>
        </div>
        
        <h1>🤖 AI自适应防御决策系统演示</h1>
        
        <!-- 系统状态 -->
        <div class="status-grid">
            <div class="status-item">
                <div>系统状态</div>
                <div class="status-value"><?php echo $system_status['system_health']; ?></div>
            </div>
            <div class="status-item">
                <div>活跃威胁</div>
                <div class="status-value"><?php echo $system_status['active_threats']; ?></div>
            </div>
            <div class="status-item">
                <div>封禁IP</div>
                <div class="status-value"><?php echo $system_status['blocked_ips_count']; ?></div>
            </div>
            <div class="status-item">
                <div>防御策略</div>
                <div class="status-value"><?php echo $system_status['defense_strategies_count']; ?></div>
            </div>
        </div>
        
        <!-- 威胁检测表单 -->
        <form method="POST">
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
        
        <div class="result-box">
            <h3>检测结果详情：</h3>
            <p><strong>威胁等级：</strong> <?php echo strtoupper($result['threat_level']); ?></p>
            <p><strong>威胁评分：</strong> <?php echo $result['threat_score']; ?>/100</p>
            <p><strong>客户端IP：</strong> <?php echo $result['client_ip']; ?></p>
            <?php if (!empty($result['detected_threats'])): ?>
            <p><strong>检测到的威胁：</strong> <?php echo implode(', ', $result['detected_threats']); ?></p>
            <?php endif; ?>
        </div>
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
        </div>
        
        <!-- 使用说明 -->
        <div class="examples">
            <h3>📖 如何使用：</h3>
            <p>1. <strong>直接测试</strong>：在输入框中输入要检测的内容，点击"检测威胁"</p>
            <p>2. <strong>集成到应用</strong>：在您的PHP文件开头添加以下代码：</p>
            <pre style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; overflow-x: auto;">
require_once 'ai_defense_middleware.php';
$middleware = new AIDefenseMiddleware($conn);
$middleware->processRequest();</pre>
            <p>3. <strong>API调用</strong>：通过HTTP请求调用API接口</p>
        </div>
    </div>

    <script>
        function useExample(text) {
            document.getElementById('test_input').value = text;
        }
        
        function clearForm() {
            document.getElementById('test_input').value = '';
        }
    </script>
</body>
</html> 