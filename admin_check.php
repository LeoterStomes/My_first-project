<?php
/**
 * 管理员权限检查
 * 只有管理员可以访问AI防御系统
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
?> 