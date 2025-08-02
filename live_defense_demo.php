<?php
/**
 * 实时防御演示页面
 * 展示攻击溯源和自动化修复功能
 * 管理员专用
 */

// 关闭错误输出
error_reporting(0);
ini_set('display_errors', 0);

require_once 'admin_check.php';
require_once 'db.php';
require_once 'ai_defense_system.php';
require_once 'deepseek_config.php';
require_once 'ai_defense_deepseek.php';

$ai_defense = new AIDefenseSystem($conn);
$deepseek_defense = new DeepSeekAIDefense($conn);

$demo_results = [];
$attack_trace = null;
$auto_fix = null;

// 处理演示请求
if ($_POST) {
    $demo_type = $_POST['demo_type'] ?? '';
    $attack_data = $_POST['attack_data'] ?? '';
    
    if ($demo_type && $attack_data) {
        switch ($demo_type) {
            case 'sql_injection':
                $demo_results = simulateSQLInjectionAttack($attack_data);
                break;
            case 'xss_attack':
                $demo_results = simulateXSSAttack($attack_data);
                break;
            case 'file_upload':
                $demo_results = simulateFileUploadAttack($attack_data);
                break;
            case 'csrf_attack':
                $demo_results = simulateCSRFAttack($attack_data);
                break;
        }
        
        // 执行攻击溯源
        if ($demo_results['threat_level'] !== 'low') {
            $attack_trace = $ai_defense->traceAttack($demo_results);
        }
        
        // 执行自动化修复
        if (isset($demo_results['vulnerability'])) {
            $auto_fix = $ai_defense->autoFixVulnerability($demo_results['vulnerability']);
        }
    }
}

function simulateSQLInjectionAttack($data) {
    global $ai_defense;
    
    $request_data = [
        'client_ip' => $_SERVER['REMOTE_ADDR'],
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Demo Agent',
        'payload' => $data,
        'timestamp' => date('Y-m-d H:i:s')
    ];
    
    $threat_analysis = $ai_defense->detectThreat($data);
    
    return array_merge($threat_analysis, [
        'attack_type' => 'sql_injection',
        'vulnerability' => [
            'type' => 'sql_injection',
            'file' => 'example_file.php',
            'line' => 15,
            'description' => '发现SQL注入漏洞'
        ]
    ]);
}

function simulateXSSAttack($data) {
    global $ai_defense;
    
    $threat_analysis = $ai_defense->detectThreat($data);
    
    return array_merge($threat_analysis, [
        'attack_type' => 'xss',
        'vulnerability' => [
            'type' => 'xss',
            'file' => 'display.php',
            'line' => 23,
            'description' => '发现XSS漏洞'
        ]
    ]);
}

function simulateFileUploadAttack($data) {
    global $ai_defense;
    
    $threat_analysis = $ai_defense->detectThreat($data);
    
    return array_merge($threat_analysis, [
        'attack_type' => 'file_upload',
        'vulnerability' => [
            'type' => 'file_upload',
            'file' => 'upload.php',
            'line' => 45,
            'description' => '发现文件上传漏洞'
        ]
    ]);
}

function simulateCSRFAttack($data) {
    global $ai_defense;
    
    $threat_analysis = $ai_defense->detectThreat($data);
    
    return array_merge($threat_analysis, [
        'attack_type' => 'csrf',
        'vulnerability' => [
            'type' => 'csrf',
            'file' => 'admin.php',
            'line' => 67,
            'description' => '发现CSRF漏洞'
        ]
    ]);
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>实时防御演示 - AI防御系统</title>
    <link rel="icon" type="image/png" href="logo.png">
    <link rel="stylesheet" href="style.css">
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        
        .demo-container {
            background: rgba(255,255,255,0.1);
            padding: 30px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
            margin-bottom: 30px;
        }
        
        .demo-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .demo-header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .demo-form {
            background: rgba(255,255,255,0.1);
            padding: 25px;
            border-radius: 10px;
            margin-bottom: 30px;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
        }
        
        .form-group select,
        .form-group textarea {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            background: rgba(255,255,255,0.9);
            color: #333;
            font-size: 14px;
        }
        
        .form-group textarea {
            height: 100px;
            resize: vertical;
        }
        
        .demo-btn {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .demo-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(255, 107, 107, 0.4);
        }
        
        .results-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-top: 30px;
        }
        
        .result-card {
            background: rgba(255,255,255,0.1);
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid #ff6b6b;
        }
        
        .result-card.success {
            border-left-color: #2ed573;
        }
        
        .result-card.warning {
            border-left-color: #ffa502;
        }
        
        .result-card.critical {
            border-left-color: #ff4757;
        }
        
        .result-card h3 {
            margin-bottom: 15px;
            font-size: 1.3em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .result-details {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            margin-top: 15px;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 200px;
            overflow-y: auto;
        }
        
        .threat-level {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.9em;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .threat-level.low {
            background: #2ed573;
        }
        
        .threat-level.medium {
            background: #ffa502;
        }
        
        .threat-level.high {
            background: #ff4757;
        }
        
        .threat-level.critical {
            background: #ff4757;
            animation: pulse 2s infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 1; }
            50% { opacity: 0.7; }
            100% { opacity: 1; }
        }
        
        .fix-actions {
            background: linear-gradient(135deg, #2ed573 0%, #17c0eb 100%);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        
        .fix-actions h4 {
            margin-bottom: 15px;
            color: white;
        }
        
        .fix-action-item {
            background: rgba(255,255,255,0.2);
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
        }
        
        .trace-chain {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
        }
        
        .trace-chain h4 {
            margin-bottom: 15px;
            color: white;
        }
        
        .chain-item {
            background: rgba(255,255,255,0.1);
            padding: 10px 15px;
            border-radius: 5px;
            margin-bottom: 10px;
            border-left: 3px solid #48dbfb;
        }
        
        .back-btn {
            display: inline-block;
            background: rgba(255,255,255,0.2);
            color: white;
            text-decoration: none;
            padding: 10px 20px;
            border-radius: 5px;
            margin-top: 20px;
            transition: background 0.3s;
        }
        
        .back-btn:hover {
            background: rgba(255,255,255,0.3);
        }
    </style>
</head>
<body>
    <div class="demo-container">
        <div class="demo-header">
            <h1>🛡️ 实时防御演示</h1>
            <p>模拟真实攻击场景，展示AI防御系统的攻击溯源和自动化修复功能</p>
        </div>

        <div class="demo-form">
            <form method="POST">
                <div class="form-group">
                    <label for="demo_type">选择攻击类型：</label>
                    <select name="demo_type" id="demo_type" required>
                        <option value="">请选择攻击类型</option>
                        <option value="sql_injection">SQL注入攻击</option>
                        <option value="xss_attack">XSS跨站脚本攻击</option>
                        <option value="file_upload">恶意文件上传</option>
                        <option value="csrf_attack">CSRF跨站请求伪造</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label for="attack_data">攻击载荷：</label>
                    <textarea name="attack_data" id="attack_data" placeholder="输入攻击载荷..." required></textarea>
                </div>
                
                <button type="submit" class="demo-btn">🚀 执行攻击演示</button>
            </form>
        </div>

        <?php if (!empty($demo_results)): ?>
        <div class="results-grid">
            <!-- 威胁检测结果 -->
            <div class="result-card <?php echo $demo_results['threat_level']; ?>">
                <h3>
                    🔍 威胁检测结果
                    <span class="threat-level <?php echo $demo_results['threat_level']; ?>">
                        <?php echo strtoupper($demo_results['threat_level']); ?>
                    </span>
                </h3>
                <p><strong>威胁评分：</strong> <?php echo $demo_results['score']; ?></p>
                <p><strong>攻击类型：</strong> <?php echo ucfirst($demo_results['attack_type']); ?></p>
                <p><strong>检测到的威胁：</strong> <?php echo $demo_results['threats_detected']; ?></p>
                <div class="result-details">
<?php echo json_encode($demo_results, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE); ?>
                </div>
            </div>

            <?php if ($attack_trace): ?>
            <!-- 攻击溯源结果 -->
            <div class="result-card">
                <h3>🔍 攻击溯源分析</h3>
                <div class="trace-chain">
                    <h4>📊 溯源结果</h4>
                    <p><strong>攻击链长度：</strong> <?php echo $attack_trace['chain_length']; ?></p>
                    <p><strong>攻击模式：</strong> <?php echo $attack_trace['attack_pattern']; ?></p>
                    <p><strong>攻击源：</strong> <?php echo $attack_trace['source']['ip_geolocation']['country']; ?></p>
                    
                    <h4>🎯 建议措施</h4>
                    <?php foreach ($attack_trace['recommendations'] as $rec): ?>
                    <div class="chain-item">• <?php echo $rec; ?></div>
                    <?php endforeach; ?>
                </div>
            </div>
            <?php endif; ?>

            <?php if ($auto_fix): ?>
            <!-- 自动化修复结果 -->
            <div class="result-card success">
                <h3>🔧 自动化修复</h3>
                <div class="fix-actions">
                    <h4>✅ 修复操作</h4>
                    <div class="fix-action-item">
                        <strong>修复类型：</strong> <?php echo $auto_fix['action']; ?>
                    </div>
                    <div class="fix-action-item">
                        <strong>文件路径：</strong> <?php echo $auto_fix['file']; ?>
                    </div>
                    <div class="fix-action-item">
                        <strong>修复行号：</strong> <?php echo $auto_fix['line']; ?>
                    </div>
                    <div class="fix-action-item">
                        <strong>修复描述：</strong> <?php echo $auto_fix['description']; ?>
                    </div>
                </div>
            </div>
            <?php endif; ?>
        </div>
        <?php endif; ?>

        <a href="admin_ai_defense.php" class="back-btn">← 返回AI防御系统</a>
    </div>

    <script>
        // 根据选择的攻击类型自动填充示例载荷
        document.getElementById('demo_type').addEventListener('change', function() {
            const attackData = document.getElementById('attack_data');
            const selectedType = this.value;
            
            const examples = {
                'sql_injection': "admin' OR 1=1--\npassword=123456",
                'xss_attack': '&lt;script&gt;alert(\"XSS\")&lt;/script&gt;\n&lt;img src=\"x\" onerror=\"alert(\\'test\\')\"&gt;',
                'file_upload': 'shell.php\n&lt;?php system($_GET[\"cmd\"]); ?&gt;',
                'csrf_attack': '&lt;form action=\"http://target.com/admin/delete\" method=\"POST\"&gt;\n&lt;input type=\"hidden\" name=\"id\" value=\"1\"&gt;\n&lt;/form&gt;'
            };
            
            if (examples[selectedType]) {
                attackData.value = examples[selectedType];
            }
        });
    </script>
</body>
</html> 