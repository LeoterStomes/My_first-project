-- AI自适应防御决策系统数据库表结构
-- 基于现有数据库 aibachang

-- 防御策略表
CREATE TABLE IF NOT EXISTS `defense_strategies` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL COMMENT '策略名称',
  `description` text COMMENT '策略描述',
  `action` varchar(50) NOT NULL COMMENT '防御动作',
  `priority` int(11) DEFAULT 1 COMMENT '优先级',
  `active` tinyint(1) DEFAULT 1 COMMENT '是否启用',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 攻击模式表
CREATE TABLE IF NOT EXISTS `attack_patterns` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL COMMENT '攻击模式名称',
  `description` text COMMENT '攻击模式描述',
  `patterns` json NOT NULL COMMENT '匹配模式(JSON格式)',
  `severity` int(11) DEFAULT 10 COMMENT '严重程度(1-100)',
  `active` tinyint(1) DEFAULT 1 COMMENT '是否启用',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 封禁IP表
CREATE TABLE IF NOT EXISTS `blocked_ips` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL COMMENT 'IP地址',
  `reason` varchar(255) NOT NULL COMMENT '封禁原因',
  `active` tinyint(1) DEFAULT 1 COMMENT '是否有效',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `expires_at` timestamp NULL COMMENT '过期时间',
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 请求日志表
CREATE TABLE IF NOT EXISTS `request_logs` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL COMMENT '客户端IP',
  `user_agent` text COMMENT '用户代理',
  `request_method` varchar(10) NOT NULL COMMENT '请求方法',
  `request_uri` text NOT NULL COMMENT '请求URI',
  `request_data` text COMMENT '请求数据',
  `response_code` int(11) DEFAULT 200 COMMENT '响应码',
  `threat_score` int(11) DEFAULT 0 COMMENT '威胁评分',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 攻击日志表
CREATE TABLE IF NOT EXISTS `attack_logs` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL COMMENT '攻击源IP',
  `attack_type` varchar(50) NOT NULL COMMENT '攻击类型',
  `action` varchar(100) NOT NULL COMMENT '攻击动作',
  `payload` text COMMENT '攻击载荷',
  `result` varchar(50) DEFAULT 'blocked' COMMENT '处理结果',
  `threat_level` enum('low','medium','high','critical') DEFAULT 'medium' COMMENT '威胁等级',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_attack_type` (`attack_type`),
  KEY `idx_created_at` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 策略执行记录表
CREATE TABLE IF NOT EXISTS `strategy_executions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `strategy_id` int(11) UNSIGNED NOT NULL COMMENT '策略ID',
  `threat_data` json COMMENT '威胁数据',
  `success` tinyint(1) DEFAULT 1 COMMENT '是否成功',
  `execution_time` decimal(10,3) COMMENT '执行时间(秒)',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_strategy_id` (`strategy_id`),
  KEY `idx_created_at` (`created_at`),
  FOREIGN KEY (`strategy_id`) REFERENCES `defense_strategies` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 修复操作记录表
CREATE TABLE IF NOT EXISTS `fix_actions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `vulnerability_type` varchar(50) NOT NULL COMMENT '漏洞类型',
  `file_path` varchar(255) NOT NULL COMMENT '文件路径',
  `line_number` int(11) COMMENT '行号',
  `actions` json NOT NULL COMMENT '修复操作',
  `status` enum('pending','applied','failed') DEFAULT 'pending' COMMENT '状态',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  `applied_at` timestamp NULL COMMENT '应用时间',
  PRIMARY KEY (`id`),
  KEY `idx_vulnerability_type` (`vulnerability_type`),
  KEY `idx_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 阻断操作记录表
CREATE TABLE IF NOT EXISTS `block_actions` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL COMMENT 'IP地址',
  `threat_level` enum('low','medium','high','critical') NOT NULL COMMENT '威胁等级',
  `threat_score` int(11) NOT NULL COMMENT '威胁评分',
  `actions` json NOT NULL COMMENT '阻断操作',
  `created_at` timestamp DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_ip_address` (`ip_address`),
  KEY `idx_threat_level` (`threat_level`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 威胁情报表
CREATE TABLE IF NOT EXISTS `threat_intelligence` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `ip_address` varchar(45) NOT NULL COMMENT 'IP地址',
  `reputation` enum('good','neutral','bad','unknown') DEFAULT 'unknown' COMMENT '信誉度',
  `threat_score` int(11) DEFAULT 0 COMMENT '威胁评分',
  `known_malicious` tinyint(1) DEFAULT 0 COMMENT '已知恶意',
  `source` varchar(100) COMMENT '情报来源',
  `last_updated` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ip_address` (`ip_address`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 系统配置表
CREATE TABLE IF NOT EXISTS `system_config` (
  `id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT,
  `config_key` varchar(100) NOT NULL COMMENT '配置键',
  `config_value` text NOT NULL COMMENT '配置值',
  `description` text COMMENT '配置描述',
  `updated_at` timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_config_key` (`config_key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 插入默认防御策略
INSERT INTO `defense_strategies` (`name`, `description`, `action`, `priority`) VALUES
('SQL注入防护', '检测和阻止SQL注入攻击', 'sql_injection_protection', 10),
('XSS防护', '检测和阻止跨站脚本攻击', 'xss_protection', 9),
('CSRF防护', '检测和阻止跨站请求伪造攻击', 'csrf_protection', 8),
('文件上传防护', '检测和阻止恶意文件上传', 'file_upload_protection', 7),
('暴力破解防护', '检测和阻止暴力破解攻击', 'brute_force_protection', 6),
('DDoS防护', '检测和阻止分布式拒绝服务攻击', 'ddos_protection', 5),
('异常行为检测', '检测异常的用户行为模式', 'anomaly_detection', 4),
('IP信誉检查', '基于IP信誉度进行防护', 'ip_reputation_check', 3);

-- 插入默认攻击模式
INSERT INTO `attack_patterns` (`name`, `description`, `patterns`, `severity`) VALUES
('SQL注入', 'SQL注入攻击模式', '["/.*[;\\\'\"].*[=<>].*/", "/.*UNION.*SELECT.*/", "/.*DROP.*TABLE.*/"]', 90),
('XSS攻击', '跨站脚本攻击模式', '["/<script.*>/i", "/javascript:/i", "/on\\w+\\s*=/i"]', 80),
('文件包含', '文件包含攻击模式', '["/.*\\.\\./.*", "/.*php://.*/", "/.*data://.*/"]', 85),
('命令注入', '命令注入攻击模式', '["/.*[;&|`].*[a-z]+.*/", "/.*\\$\\{.*\\}.*/"]', 95),
('路径遍历', '路径遍历攻击模式', '["/.*\\.\\./.*", "/.*%2e%2e/.*"]', 75),
('CSRF攻击', '跨站请求伪造攻击模式', '["/.*<img.*src=.*>/i", "/.*<iframe.*src=.*>/i"]', 70);

-- 插入系统配置
INSERT INTO `system_config` (`config_key`, `config_value`, `description`) VALUES
('threat_detection_enabled', '1', '是否启用威胁检测'),
('auto_block_enabled', '1', '是否启用自动封禁'),
('emergency_mode_enabled', '0', '是否启用紧急模式'),
('rate_limit_requests', '100', '速率限制请求数'),
('rate_limit_window', '3600', '速率限制时间窗口(秒)'),
('max_threat_score', '100', '最大威胁评分'),
('block_duration', '86400', '封禁持续时间(秒)'),
('log_retention_days', '30', '日志保留天数');

-- 创建索引优化查询性能
CREATE INDEX idx_request_logs_ip_time ON request_logs(ip_address, created_at);
CREATE INDEX idx_attack_logs_ip_time ON attack_logs(ip_address, created_at);
CREATE INDEX idx_strategy_executions_time ON strategy_executions(created_at); 