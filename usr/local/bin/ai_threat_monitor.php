#!/usr/local/bin/php
<?php
/*
 * ai_threat_monitor.php
 * pfSense AI Threat Monitor Daemon
 */
require_once("/etc/inc/ai.inc");
require_once("/etc/inc/util.inc");

declare(ticks = 1);

function drop_privs() {
    if (function_exists('posix_setuid') && function_exists('posix_getpwnam')) {
        $pw = posix_getpwnam('nobody');
        if ($pw) {
            posix_setgid($pw['gid']);
            posix_setuid($pw['uid']);
        }
    }
}

function tail_log($path, &$last_inode, &$last_pos) {
    $lines = [];
    if (!file_exists($path)) return $lines;
    $f = new SplFileObject($path, 'r');
    $inode = fileinode($path);
    if ($last_inode !== $inode) {
        $f->seek(PHP_INT_MAX);
        $last_pos = $f->ftell();
        $last_inode = $inode;
        return [];
    }
    $f->fseek($last_pos ?? 0);
    while (!$f->eof()) {
        $line = $f->fgets();
        if (strlen(trim($line))) $lines[] = trim($line);
    }
    $last_pos = $f->ftell();
    return $lines;
}

function parse_ip($line) {
    if (preg_match('/((?:\d{1,3}\.){3}\d{1,3})/', $line, $m)) return $m[1];
    if (preg_match('/([a-fA-F0-9:]{3,})/', $line, $m)) return $m[1];
    return null;
}

function pfctl_block($ip) {
    mwexec('/sbin/pfctl -t ai_blocklist -T add ' . escapeshellarg($ip));
}
function pfctl_create() {
    mwexec('/sbin/pfctl -t ai_blocklist -T show 2>/dev/null || /sbin/pfctl -t ai_blocklist -T create');
}
function blocklist_add($ip, $reason) {
    $file = '/var/db/ai_blocklist.json';
    $rec = [ 'ip' => $ip, 'reason' => $reason, 'ts' => date('c') ];
    $rows = [];
    if (file_exists($file)) {
        $rows = json_decode(file_get_contents($file), true);
        if (!is_array($rows)) $rows = [];
    }
    // Remove old entry for this IP
    $rows = array_filter($rows, fn($row) => $row['ip'] !== $ip);
    $rows[] = $rec;
    file_put_contents($file, json_encode(array_values($rows)));
}

function is_blocked($ip) {
    $file = '/var/db/ai_blocklist.json';
    if (!file_exists($file)) return false;
    $rows = json_decode(file_get_contents($file), true);
    if (!is_array($rows)) return false;
    foreach ($rows as $row) if ($row['ip'] === $ip) return true;
    return false;
}

function syslog_notice($msg) {
    openlog("pfSense/AI", LOG_PID, LOG_USER);
    syslog(LOG_NOTICE, $msg);
    closelog();
}

function lru_cache(&$cache, $ip, $max = 1000) {
    if (isset($cache[$ip])) {
        unset($cache[$ip]);
    }
    $cache[$ip] = time();
    if (count($cache) > $max) {
        array_shift($cache);
    }
}

$running = true;
pcntl_signal(SIGTERM, function() use (&$running) { $running = false; });
pcntl_signal(SIGINT, function() use (&$running) { $running = false; });

drop_privs();
pfctl_create();

$filterlog = '/var/log/filter.log';
$snort_dir = '/var/log/snort/';
$snort_logs = [];
if (is_dir($snort_dir)) {
    foreach (glob($snort_dir . '*/fast.log') as $log) $snort_logs[] = $log;
}
$log_files = array_merge([$filterlog], $snort_logs);

$pos = $inode = [];
$lru = [];

while ($running) {
    foreach ($log_files as $idx => $log) {
        $lines = tail_log($log, $inode[$log], $pos[$log]);
        foreach ($lines as $line) {
            $ip = parse_ip($line);
            if (!$ip || is_blocked($ip) || isset($lru[$ip])) continue;
            lru_cache($lru, $ip, 5000);
            $prompt = 'You are a network security expert. Evaluate the following log line. If it indicates malicious or suspicious activity return exactly JSON {"action":"block","reason":"<short>"}.' .
                      ' Otherwise return JSON {"action":"ignore"}. Log line: ' . $line;
            try {
                $provider_name = ($GLOBALS['config']['system']['ai']['default_provider'] ?? 'gemini');
                $provider = AIProviderFactory::make($provider_name);
                $reply = $provider->send_chat([$prompt]);
                $json = json_decode(trim($reply), true);
                if (isset($json['action']) && $json['action'] === 'block' && !empty($json['reason'])) {
                    pfctl_block($ip);
                    blocklist_add($ip, $json['reason']);
                    syslog_notice("AI blocked $ip: " . $json['reason']);
                }
            } catch (\Exception $e) {
                syslog_notice("AI Threat Monitor error: " . $e->getMessage());
            }
        }
    }
    sleep(5);
}