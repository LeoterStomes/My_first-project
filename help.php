<?php
/**
 * help.php
 * 帮助中心页面，提供各个靶场的说明
 */
session_start();

// 检查用户是否登录
if (!isset($_SESSION['username'])) {
    header("Location: login.php");
    exit();
}
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>帮助中心 - 东海学院网络靶场</title>
    <link rel="icon" type="image/png" href="logo.png">
    <link rel="stylesheet" href="style.css">
    <style>
        .help-section {
            margin-bottom: 25px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        .help-section:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        .help-section h3 {
            color: #007bff;
            margin-top: 0;
        }
        .help-section p {
            color: #444;
            line-height: 1.8;
        }
        .help-section code {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 3px;
            padding: 2px 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #e83e8c;
        }
    </style>
</head>
<body>
    <div class="dashboard-header">
        <div class="header-content">
            <h1><a href="dashboard.php">东海学院网络靶场 控制板</a></h1>
            <div class="user-menu">
                <span>欢迎, <?php echo htmlspecialchars($_SESSION['nickname'] ?: $_SESSION['username']); ?></span>
                <a href="profile.php" class="btn-profile">个人资料</a>
                <a href="logout.php" class="btn-logout">退出登录</a>
            </div>
        </div>
    </div>

    <div class="main-content">
        <div class="profile-card">
            <h2>帮助中心</h2>
            
            <div class="help-section">
                <h3>暴力破解 (Brute Force)</h3>
                <p>
                    <strong>核心概念：</strong> 通过穷举所有可能的密码组合来破解账户。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接尝试常见用户名（admin、root、test）和密码（123456、password、admin）<br>
                    • <strong>Level 2：</strong> 使用自动化工具，注意服务器可能有延迟机制<br>
                    • <strong>Level 3：</strong> 需要绕过CSRF Token，先获取Token再提交<br>
                    • <strong>Level 4：</strong> 结合Token验证和账户锁定，需要更精细的策略<br>
                    <strong>学习价值：</strong> 理解密码策略的重要性，学会使用Burp Suite等工具进行自动化攻击。
                </p>
            </div>

            <div class="help-section">
                <h3>命令注入 (Command Injection)</h3>
                <p>
                    <strong>核心概念：</strong> 利用应用程序直接执行系统命令的漏洞。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接注入 <code>&</code>、<code>&&</code>、<code>|</code>、<code>;</code> 等命令连接符，例如：<code>127.0.0.1 & whoami</code>、<code>127.0.0.1 && cat /etc/passwd</code><br>
                    • <strong>Level 2：</strong> 过滤了 <code>&&</code> 和 <code>;</code>，尝试 <code>&</code> 或 <code>|</code><br>
                    • <strong>Level 3：</strong> 过滤更多字符，尝试换行符 <code>\n</code> 或编码绕过<br>
                    • <strong>Level 4：</strong> 严格验证IP格式，几乎无法注入<br>
                    <strong>学习价值：</strong> 掌握命令注入的检测和绕过技巧，理解输入验证的重要性。
                </p>
            </div>

            <div class="help-section">
                <h3>跨站请求伪造 (CSRF)</h3>
                <p>
                    <strong>核心概念：</strong> 诱导已登录用户执行非本意操作的攻击。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接修改密码，无任何防护<br>
                    • <strong>Level 2：</strong> 需要绕过Referer检查，构造恶意页面<br>
                    • <strong>Level 3：</strong> 需要CSRF Token，先获取Token再构造请求<br>
                    • <strong>Level 4：</strong> 需要当前密码验证，几乎无法攻击<br>
                    <strong>学习价值：</strong> 理解CSRF攻击原理，学会构造恶意请求和绕过防护。
                </p>
            </div>

            <div class="help-section">
                <h3>文件包含 (File Inclusion)</h3>
                <p>
                    <strong>核心概念：</strong> 利用应用程序包含文件的漏洞读取或执行任意文件。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接包含系统文件，如 <code>../../../etc/passwd</code><br>
                    • <strong>Level 2：</strong> 过滤 <code>../</code>，尝试编码绕过或绝对路径<br>
                    • <strong>Level 3：</strong> 只允许包含特定目录，尝试路径遍历<br>
                    • <strong>Level 4：</strong> 白名单验证，几乎无法绕过<br>
                    <strong>学习价值：</strong> 掌握路径遍历技巧，理解文件包含漏洞的危害。
                </p>
            </div>

            <div class="help-section">
                <h3>文件上传 (File Upload)</h3>
                <p>
                    <strong>核心概念：</strong> 绕过文件上传限制，上传恶意文件控制服务器。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接上传PHP文件，如 <code>shell.php</code><br>
                    • <strong>Level 2：</strong> 检查文件扩展名，尝试双扩展名如 <code>shell.php.jpg</code><br>
                    • <strong>Level 3：</strong> 检查文件内容，尝试在图片中嵌入PHP代码<br>
                    • <strong>Level 4：</strong> 多重验证，需要更复杂的绕过技巧<br>
                    <strong>学习价值：</strong> 理解文件上传安全机制，学会各种绕过技巧。
                </p>
            </div>

            <div class="help-section">
                <h3>不安全的验证码 (Insecure CAPTCHA)</h3>
                <p>
                    <strong>核心概念：</strong> 利用验证码生成或验证逻辑的漏洞。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 验证码固定为1234，直接输入即可<br>
                    • <strong>Level 2：</strong> 验证码简单可预测，尝试暴力破解<br>
                    • <strong>Level 3：</strong> 验证码复杂但仍可分析，尝试重放攻击<br>
                    • <strong>Level 4：</strong> 模拟图形验证码，但仍有逻辑漏洞<br>
                    <strong>学习价值：</strong> 理解验证码安全设计，学会绕过验证码保护。
                </p>
            </div>

            <div class="help-section">
                <h3>SQL注入 (SQL Injection)</h3>
                <p>
                    <strong>核心概念：</strong> 在数据库查询中注入恶意SQL语句。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接注入，如 <code>1' OR '1'='1</code>、<code>1; DROP TABLE users;--</code><br>
                    • <strong>Level 2：</strong> 过滤关键字，尝试大小写混淆或注释绕过<br>
                    • <strong>Level 3：</strong> 只允许数字，尝试类型转换或编码绕过<br>
                    • <strong>Level 4：</strong> 预处理语句，几乎无法注入<br>
                    <strong>学习价值：</strong> 掌握SQL注入的检测和利用技巧，理解数据库安全。
                </p>
            </div>

            <div class="help-section">
                <h3>SQL盲注 (SQLi - Blind)</h3>
                <p>
                    <strong>核心概念：</strong> 在无回显的情况下通过布尔逻辑推断数据。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 使用布尔型盲注，如 <code>1' AND length(username)=5--</code><br>
                    • <strong>Level 2：</strong> 过滤关键字，尝试编码或注释绕过<br>
                    • <strong>Level 3：</strong> 只允许数字，尝试类型转换<br>
                    • <strong>Level 4：</strong> 预处理语句防护<br>
                    <strong>学习价值：</strong> 掌握盲注技巧，学会通过间接方式获取数据。
                </p>
            </div>

            <div class="help-section">
                <h3>反射型XSS (Reflected XSS)</h3>
                <p>
                    <strong>核心概念：</strong> 恶意脚本通过URL参数反射到页面执行。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接注入 <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code><br>
                    • <strong>Level 2：</strong> 过滤script标签，尝试事件属性如 <code>onerror=alert(1)</code><br>
                    • <strong>Level 3：</strong> 严格字符过滤，尝试编码绕过<br>
                    • <strong>Level 4：</strong> 完全转义，几乎无法注入<br>
                    <strong>学习价值：</strong> 理解XSS攻击原理，学会构造恶意脚本。
                </p>
            </div>

            <div class="help-section">
                <h3>存储型XSS (Stored XSS)</h3>
                <p>
                    <strong>核心概念：</strong> 恶意脚本存储在服务器中，影响所有访问用户。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接提交恶意脚本到留言板<br>
                    • <strong>Level 2：</strong> 过滤部分标签，尝试其他标签或事件属性<br>
                    • <strong>Level 3：</strong> 严格字符限制，尝试编码绕过<br>
                    • <strong>Level 4：</strong> 完全转义防护<br>
                    <strong>学习价值：</strong> 理解存储型XSS的危害，学会检测和防护。
                </p>
            </div>

            <div class="help-section">
                <h3>DOM型XSS (DOM Based XSS)</h3>
                <p>
                    <strong>核心概念：</strong> 通过前端JavaScript操作DOM实现脚本注入。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 直接修改URL参数，如 <code>?message=&lt;script&gt;alert(1)&lt;/script&gt;</code><br>
                    • <strong>Level 2：</strong> 过滤script标签，尝试其他标签<br>
                    • <strong>Level 3：</strong> 字符限制，尝试编码绕过<br>
                    • <strong>Level 4：</strong> 完全转义防护<br>
                    <strong>学习价值：</strong> 理解DOM操作安全，学会前端漏洞利用。
                </p>
            </div>

            <div class="help-section">
                <h3>弱会话ID (Weak Session IDs)</h3>
                <p>
                    <strong>核心概念：</strong> 利用可预测的会话标识符进行会话劫持。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> 会话ID为简单数字，容易预测<br>
                    • <strong>Level 2：</strong> 会话ID复杂但仍可分析规律<br>
                    • <strong>Level 3：</strong> 会话ID更复杂，需要更深入分析<br>
                    • <strong>Level 4：</strong> 使用加密随机数，几乎无法预测<br>
                    <strong>学习价值：</strong> 理解会话管理安全，学会会话劫持技术。
                </p>
            </div>

            <div class="help-section">
                <h3>绕过内容安全策略 (CSP)</h3>
                <p>
                    <strong>核心概念：</strong> 绕过CSP限制执行恶意脚本。<br>
                    <strong>实战要点：</strong><br>
                    • <strong>Level 1：</strong> CSP配置宽松，容易绕过<br>
                    • <strong>Level 2：</strong> CSP限制部分资源，尝试其他绕过方式<br>
                    • <strong>Level 3：</strong> CSP较严格，需要更复杂的绕过技巧<br>
                    • <strong>Level 4：</strong> CSP配置完善，几乎无法绕过<br>
                    <strong>学习价值：</strong> 理解CSP防护机制，学会绕过技巧。
                </p>
            </div>

            <div class="help-section">
                <h3>🎯 学习建议</h3>
                <p>
                    <strong>循序渐进：</strong> 从Level 1开始，逐步提升难度<br>
                    <strong>工具使用：</strong> 学会使用Burp Suite、OWASP ZAP等工具<br>
                    <strong>代码分析：</strong> 理解每个靶场的源代码和防护逻辑<br>
                    <strong>实战练习：</strong> 在真实环境中练习这些技术<br>
                    <strong>防护学习：</strong> 不仅要学会攻击，更要理解如何防护
                </p>
                <p style="color: #d48806; font-weight: bold;">
                    这些靶场涵盖了Web安全的核心漏洞类型，通过系统学习可以建立完整的安全知识体系！
                </p>
            </div>

            <div class="form-actions" style="margin-top: 25px;">
                <a href="dashboard.php" class="btn-cancel">返回控制板</a>
            </div>

        </div>
    </div>

    <footer class="site-footer">
        <p>版权所有 &copy; <?php echo date("Y"); ?> 上海市东海职业技术学院</p>
        <p><a href="https://beian.miit.gov.cn/" target="_blank">沪ICP备2025126528号-1</a></p>
    </footer>
</body>
</html> 