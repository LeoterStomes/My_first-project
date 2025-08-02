<?php
/**
 * AI自适应防御决策系统管理仪表板
 * 管理员专用
 */

require_once 'admin_check.php';
require_once 'db.php';
require_once 'ai_defense_system.php';

// 初始化AI防御系统
$ai_defense = new AIDefenseSystem($conn);

// 获取系统状态
$system_status = $ai_defense->getSystemStatus();

// 获取统计数据
$stats = getSystemStats($conn);

function getSystemStats($conn) {
    $stats = [];
    
    // 今日攻击次数
    $sql = "SELECT COUNT(*) as count FROM attack_logs WHERE DATE(created_at) = CURDATE()";
    $result = $conn->query($sql);
    $stats['today_attacks'] = $result->fetch_assoc()['count'];
    
    // 封禁IP数量
    $sql = "SELECT COUNT(*) as count FROM blocked_ips WHERE active = 1";
    $result = $conn->query($sql);
    $stats['blocked_ips'] = $result->fetch_assoc()['count'];
    
    // 活跃威胁
    $sql = "SELECT COUNT(*) as count FROM attack_logs WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)";
    $result = $conn->query($sql);
    $stats['active_threats'] = $result->fetch_assoc()['count'];
    
    // 修复操作数量
    $sql = "SELECT COUNT(*) as count FROM fix_actions WHERE status = 'applied'";
    $result = $conn->query($sql);
    $stats['applied_fixes'] = $result->fetch_assoc()['count'];
    
    return $stats;
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI自适应防御决策系统</title>
    <link rel="stylesheet" href="style.css">
    <style>
        .dashboard-container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .status-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .status-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .status-card.critical {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        }
        
        .status-card.warning {
            background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%);
        }
        
        .status-card.success {
            background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
        }
        
        .card-title {
            font-size: 14px;
            opacity: 0.9;
            margin-bottom: 10px;
        }
        
        .card-value {
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .card-change {
            font-size: 12px;
            opacity: 0.8;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: 2fr 1fr;
            gap: 30px;
        }
        
        .chart-container {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .chart-title {
            font-size: 18px;
            font-weight: bold;
            margin-bottom: 20px;
            color: #333;
        }
        
        .recent-activity {
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .activity-item {
            padding: 15px 0;
            border-bottom: 1px solid #eee;
        }
        
        .activity-item:last-child {
            border-bottom: none;
        }
        
        .activity-time {
            font-size: 12px;
            color: #666;
        }
        
        .activity-text {
            margin: 5px 0;
            color: #333;
        }
        
        .threat-level {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        
        .threat-level.critical {
            background: #ff4757;
            color: white;
        }
        
        .threat-level.high {
            background: #ffa502;
            color: white;
        }
        
        .threat-level.medium {
            background: #ff6348;
            color: white;
        }
        
        .threat-level.low {
            background: #2ed573;
            color: white;
        }
        
        .control-panel {
            background: white;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .control-button {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            margin: 5px;
            font-size: 14px;
        }
        
        .control-button:hover {
            opacity: 0.9;
        }
        
        .control-button.danger {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%);
        }
        
        .control-button.success {
            background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%);
        }
    </style>
</head>
<body>
    <div class="dashboard-container">
        <h1>🤖 AI自适应防御决策系统</h1>
        
        <!-- 状态卡片 -->
        <div class="status-cards">
            <div class="status-card <?php echo $stats['active_threats'] > 10 ? 'critical' : 'success'; ?>">
                <div class="card-title">活跃威胁</div>
                <div class="card-value"><?php echo $stats['active_threats']; ?></div>
                <div class="card-change">过去1小时</div>
            </div>
            
            <div class="status-card <?php echo $stats['today_attacks'] > 50 ? 'warning' : 'success'; ?>">
                <div class="card-title">今日攻击</div>
                <div class="card-value"><?php echo $stats['today_attacks']; ?></div>
                <div class="card-change">今日累计</div>
            </div>
            
            <div class="status-card success">
                <div class="card-title">封禁IP</div>
                <div class="card-value"><?php echo $stats['blocked_ips']; ?></div>
                <div class="card-change">当前封禁</div>
            </div>
            
            <div class="status-card success">
                <div class="card-title">已修复漏洞</div>
                <div class="card-value"><?php echo $stats['applied_fixes']; ?></div>
                <div class="card-change">自动修复</div>
            </div>
        </div>
        
        <!-- 主要内容区域 -->
        <div class="dashboard-grid">
            <!-- 图表区域 -->
            <div class="chart-container">
                <div class="chart-title">📊 威胁趋势分析</div>
                <canvas id="threatChart" width="400" height="200"></canvas>
                
                <div style="margin-top: 30px;">
                    <div class="chart-title">🛡️ 防御策略状态</div>
                    <div id="strategyStatus"></div>
                </div>
            </div>
            
            <!-- 最近活动 -->
            <div class="recent-activity">
                <div class="chart-title">⚡ 最近活动</div>
                <div id="recentActivity">
                    <!-- 动态加载活动 -->
                </div>
            </div>
        </div>
        
        <!-- 控制面板 -->
        <div class="control-panel">
            <div class="chart-title">🎛️ 系统控制</div>
            <button class="control-button" onclick="refreshSystem()">刷新系统状态</button>
            <button class="control-button success" onclick="optimizeStrategies()">优化防御策略</button>
            <button class="control-button" onclick="exportLogs()">导出安全日志</button>
            <button class="control-button danger" onclick="emergencyMode()">紧急防御模式</button>
            <button class="control-button" onclick="clearBlockedIPs()">清理过期封禁</button>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script>
        // 初始化威胁趋势图表
        const ctx = document.getElementById('threatChart').getContext('2d');
        const threatChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'],
                datasets: [{
                    label: '威胁评分',
                    data: [12, 19, 3, 5, 2, 3],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // 加载最近活动
        function loadRecentActivity() {
            fetch('ai_defense_api.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'get_recent_activity'
                })
            })
            .then(response => response.json())
            .then(data => {
                const activityContainer = document.getElementById('recentActivity');
                activityContainer.innerHTML = '';
                
                data.activities.forEach(activity => {
                    const activityItem = document.createElement('div');
                    activityItem.className = 'activity-item';
                    activityItem.innerHTML = `
                        <div class="activity-time">${activity.timestamp}</div>
                        <div class="activity-text">${activity.description}</div>
                        <span class="threat-level ${activity.threat_level}">${activity.threat_level}</span>
                    `;
                    activityContainer.appendChild(activityItem);
                });
            });
        }

        // 加载策略状态
        function loadStrategyStatus() {
            fetch('ai_defense_api.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'get_strategy_status'
                })
            })
            .then(response => response.json())
            .then(data => {
                const statusContainer = document.getElementById('strategyStatus');
                statusContainer.innerHTML = '';
                
                data.strategies.forEach(strategy => {
                    const strategyItem = document.createElement('div');
                    strategyItem.style.cssText = `
                        padding: 10px;
                        margin: 5px 0;
                        background: #f8f9fa;
                        border-radius: 5px;
                        border-left: 4px solid ${strategy.active ? '#28a745' : '#dc3545'};
                    `;
                    strategyItem.innerHTML = `
                        <strong>${strategy.name}</strong>
                        <span style="float: right; color: ${strategy.active ? '#28a745' : '#dc3545'};">
                            ${strategy.active ? '✓ 启用' : '✗ 禁用'}
                        </span>
                        <div style="font-size: 12px; color: #666;">${strategy.description}</div>
                    `;
                    statusContainer.appendChild(strategyItem);
                });
            });
        }

        // 系统控制函数
        function refreshSystem() {
            location.reload();
        }

        function optimizeStrategies() {
            fetch('ai_defense_api.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    action: 'optimize_strategies'
                })
            })
            .then(response => response.json())
            .then(data => {
                alert('防御策略优化完成！');
                loadStrategyStatus();
            });
        }

        function exportLogs() {
            window.open('ai_defense_api.php?action=export_logs', '_blank');
        }

        function emergencyMode() {
            if (confirm('确定要启用紧急防御模式吗？这将限制所有可疑活动。')) {
                fetch('ai_defense_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'emergency_mode'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    alert('紧急防御模式已启用！');
                });
            }
        }

        function clearBlockedIPs() {
            if (confirm('确定要清理过期的封禁IP吗？')) {
                fetch('ai_defense_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        action: 'clear_blocked_ips'
                    })
                })
                .then(response => response.json())
                .then(data => {
                    alert('过期封禁IP已清理！');
                    location.reload();
                });
            }
        }

        // 页面加载时初始化
        document.addEventListener('DOMContentLoaded', function() {
            loadRecentActivity();
            loadStrategyStatus();
            
            // 每30秒刷新一次活动
            setInterval(loadRecentActivity, 30000);
        });
    </script>
</body>
</html> 