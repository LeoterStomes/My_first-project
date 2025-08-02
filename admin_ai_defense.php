<?php
/**
 * 管理员AI防御系统入口
 * 只有管理员可以访问
 */

session_start();

// 检查用户是否登录
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}

// 检查是否为管理员
if ($_SESSION['username'] !== 'admin') {
    header("Location: dashboard.php");
    exit();
}

require_once 'db.php';
require_once 'deepseek_config.php';
require_once 'ai_defense_deepseek.php';
require_once 'ai_defense_system.php';

$deepseek_defense = new DeepSeekAIDefense($conn);
$traditional_defense = new AIDefenseSystem($conn);

// 测试API连接
$connection_test = $deepseek_defense->testConnection();
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI防御系统 - 管理员面板</title>
    <link rel="icon" type="image/png" href="logo.png">
    <link rel="stylesheet" href="style.css">
    <style>
        .admin-header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px 0;
            margin-bottom: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .admin-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        .admin-nav {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        
        .admin-nav h1 {
            font-size: 2.2em;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 15px;
        }
        
        .admin-nav a {
            color: white;
            text-decoration: none;
            padding: 12px 20px;
            border-radius: 8px;
            background: rgba(255,255,255,0.15);
            transition: all 0.3s ease;
            font-weight: 500;
            margin-left: 10px;
        }
        
        .admin-nav a:hover {
            background: rgba(255,255,255,0.25);
            transform: translateY(-2px);
        }
        
        .quick-stats {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-bottom: 40px;
        }
        
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .stat-label {
            color: #666;
            font-size: 1em;
            font-weight: 500;
        }
        
        .ai-defense-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 25px;
            margin-bottom: 40px;
        }
        
        .ai-defense-card {
            background: white;
            border-radius: 15px;
            padding: 30px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            border: 1px solid rgba(255,255,255,0.2);
            height: 340px;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            position: relative;
            overflow: hidden;
        }
        
        .ai-defense-card:hover {
            transform: translateY(-8px);
            box-shadow: 0 20px 40px rgba(0,0,0,0.15);
        }
        
        .ai-defense-card h3 {
            color: #333;
            margin-bottom: 15px;
            font-size: 1.4em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
            line-height: 1.3;
        }
        
        .ai-defense-card p {
            color: #666;
            margin-bottom: 25px;
            line-height: 1.6;
            flex-grow: 1;
            min-height: 90px;
            display: -webkit-box;
            -webkit-line-clamp: 4;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        
        .ai-defense-card .btn {
            display: block;
            padding: 14px 25px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            text-decoration: none;
            border-radius: 8px;
            transition: all 0.3s ease;
            font-weight: 500;
            text-align: center;
            width: 100%;
            box-sizing: border-box;
            font-size: 1em;
        }
        
        .ai-defense-card .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        
        .card-content {
            flex: 1;
            display: flex;
            flex-direction: column;
            min-height: 0;
        }
        
        .card-footer {
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #eee;
            flex-shrink: 0;
        }
        
        .status-indicator {
            display: inline-block;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }
        
        .status-online {
            background: #2ed573;
            box-shadow: 0 0 10px rgba(46, 213, 115, 0.5);
        }
        
        .status-offline {
            background: #ff4757;
            box-shadow: 0 0 10px rgba(255, 71, 87, 0.5);
        }
        
        .status-warning {
            background: #ffa502;
            box-shadow: 0 0 10px rgba(255, 165, 2, 0.5);
        }
        
        .admin-section {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 25px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            border: 1px solid rgba(255,255,255,0.2);
        }
        
        .admin-section h2 {
            color: #333;
            margin-bottom: 25px;
            border-bottom: 3px solid #667eea;
            padding-bottom: 15px;
            font-size: 1.8em;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .feature-list {
            list-style: none;
            padding: 0;
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
        }
        
        .feature-list li {
            padding: 20px;
            border-radius: 10px;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border: 1px solid #dee2e6;
            display: flex;
            align-items: flex-start;
            gap: 15px;
            transition: all 0.3s ease;
        }
        
        .feature-list li:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .feature-list li:last-child {
            border-bottom: none;
        }
        
        .feature-icon {
            font-size: 1.5em;
            margin-top: 2px;
            min-width: 30px;
        }
        
        .feature-content {
            flex: 1;
        }
        
        .feature-content strong {
            color: #333;
            font-size: 1.1em;
            display: block;
            margin-bottom: 5px;
        }
        
        .feature-content span {
            color: #666;
            line-height: 1.5;
        }
        
        .api-status {
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            padding: 20px;
            border-radius: 10px;
            border: 1px solid #dee2e6;
        }
        
        .api-status p {
            margin: 10px 0;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .api-status strong {
            color: #333;
            min-width: 120px;
        }
        
        @media (max-width: 1200px) {
            .ai-defense-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .quick-stats {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .ai-defense-card {
                height: 360px;
            }
        }
        
        @media (max-width: 768px) {
            .ai-defense-grid {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .quick-stats {
                grid-template-columns: 1fr;
            }
            
            .feature-list {
                grid-template-columns: 1fr;
            }
            
            .admin-nav {
                flex-direction: column;
                gap: 15px;
            }
            
            .admin-nav h1 {
                font-size: 1.8em;
            }
            
            .ai-defense-card {
                height: auto;
                min-height: 300px;
            }
            
            .ai-defense-card p {
                min-height: auto;
                -webkit-line-clamp: unset;
            }
        }
    </style>
</head>
<body>
    <div class="admin-header">
        <div class="admin-container">
            <div class="admin-nav">
                <h1>🤖 AI自适应防御决策系统</h1>
                <div>
                    <a href="dashboard.php">← 返回控制板</a>
                    <a href="ai_defense_dashboard.php">系统管理</a>
                    <a href="logout.php">退出登录</a>
                </div>
            </div>
        </div>
    </div>

    <div class="admin-container">
        <!-- 快速统计 -->
        <div class="quick-stats">
            <div class="stat-card">
                <div class="stat-number">
                    <span class="status-indicator <?php echo $connection_test['success'] ? 'status-online' : 'status-offline'; ?>"></span>
                    <?php echo $connection_test['success'] ? '在线' : '离线'; ?>
                </div>
                <div class="stat-label">DeepSeek AI状态</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">🛡️</div>
                <div class="stat-label">传统防御系统</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">🔄</div>
                <div class="stat-label">混合模式</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">📊</div>
                <div class="stat-label">实时监控</div>
            </div>
        </div>

        <!-- AI防御系统功能 -->
        <div class="ai-defense-grid">
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>🔍 威胁检测测试</h3>
                    <p>测试AI防御系统的威胁检测能力，输入可疑内容进行实时分析。</p>
                </div>
                <div class="card-footer">
                    <a href="demo_hybrid.php" class="btn">进入测试</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>🛡️ 实时防御演示</h3>
                    <p>模拟真实攻击场景，展示攻击溯源和自动化修复功能。</p>
                </div>
                <div class="card-footer">
                    <a href="live_defense_demo.php" class="btn">开始演示</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>🤖 纯AI模式</h3>
                    <p>使用DeepSeek AI进行智能威胁检测，提供最准确的威胁分析。</p>
                </div>
                <div class="card-footer">
                    <a href="demo_deepseek.php" class="btn">AI模式</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>🛡️ 传统模式</h3>
                    <p>基于规则和模式匹配的传统防御方法，稳定可靠。</p>
                </div>
                <div class="card-footer">
                    <a href="demo.php" class="btn">传统模式</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>📊 系统管理</h3>
                    <p>查看系统状态、管理防御策略、查看日志和统计数据。</p>
                </div>
                <div class="card-footer">
                    <a href="ai_defense_dashboard.php" class="btn">系统管理</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>🔧 系统诊断</h3>
                    <p>查看系统状态和DeepSeek API连接情况。</p>
                </div>
                <div class="card-footer">
                    <a href="ai_defense_dashboard.php" class="btn">系统状态</a>
                </div>
            </div>
            
            <div class="ai-defense-card">
                <div class="card-content">
                    <h3>📋 集成示例</h3>
                    <p>查看如何在现有应用中集成AI防御系统的代码示例。</p>
                </div>
                <div class="card-footer">
                    <a href="example_integration.php" class="btn">查看示例</a>
                </div>
            </div>
        </div>

        <!-- 系统功能说明 -->
        <div class="admin-section">
            <h2>🛡️ AI防御系统功能</h2>
            <ul class="feature-list">
                <li>
                    <span class="feature-icon">🔍</span>
                    <div class="feature-content">
                        <strong>智能威胁检测</strong>
                        <span>使用DeepSeek AI分析请求数据，识别SQL注入、XSS、命令注入等攻击</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🔄</span>
                    <div class="feature-content">
                        <strong>动态策略优化</strong>
                        <span>根据威胁等级自动调整防御策略，提供最优防护方案</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🔧</span>
                    <div class="feature-content">
                        <strong>自动漏洞修复</strong>
                        <span>AI生成具体的漏洞修复代码和建议，提高系统安全性</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🔍</span>
                    <div class="feature-content">
                        <strong>深度攻击溯源</strong>
                        <span>分析攻击链，进行深度溯源分析，识别攻击源和模式</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">📊</span>
                    <div class="feature-content">
                        <strong>实时监控统计</strong>
                        <span>提供详细的威胁统计、系统性能和日志分析</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🛡️</span>
                    <div class="feature-content">
                        <strong>混合防御模式</strong>
                        <span>AI不可用时自动切换到传统方法，确保系统稳定运行</span>
                    </div>
                </li>
            </ul>
        </div>

        <!-- 使用说明 -->
        <div class="admin-section">
            <h2>📖 使用说明</h2>
            <ul class="feature-list">
                <li>
                    <span class="feature-icon">🎯</span>
                    <div class="feature-content">
                        <strong>推荐使用混合模式</strong>
                        <span>优先使用AI检测，失败时自动切换到传统方法</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🔧</span>
                    <div class="feature-content">
                        <strong>系统集成</strong>
                        <span>在现有PHP应用中添加几行代码即可启用AI防御</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">📊</span>
                    <div class="feature-content">
                        <strong>监控管理</strong>
                        <span>通过系统管理面板查看实时状态和统计数据</span>
                    </div>
                </li>
                <li>
                    <span class="feature-icon">🛡️</span>
                    <div class="feature-content">
                        <strong>安全防护</strong>
                        <span>自动阻断恶意请求，保护系统安全</span>
                    </div>
                </li>
            </ul>
        </div>

        <!-- API状态信息 -->
        <div class="admin-section">
            <h2>🔗 API连接状态</h2>
            <div class="api-status">
                <p><strong>DeepSeek API：</strong> 
                    <span class="status-indicator <?php echo $connection_test['success'] ? 'status-online' : 'status-offline'; ?>"></span>
                    <?php echo $connection_test['success'] ? '连接正常' : '连接失败'; ?>
                </p>
                <p><strong>状态消息：</strong> <?php echo $connection_test['message']; ?></p>
                <p><strong>API密钥：</strong> sk-0ffdfe2bef9f4f93a5b0416bd272fc42</p>
            </div>
        </div>
    </div>
</body>
</html> 