#!/usr/local/bin/php
<?php
/*
 * ai_log_collector.php
 * Log Collector for AI Intelligent Defender
 * Tails logs, extracts IPs, and pushes to SQLite queue.
 * Decoupled from analysis for performance.
 */

ini_set("max_execution_time", "0");

require_once("/etc/inc/config.inc");
require_once("/etc/inc/util.inc");
require_once("/etc/inc/ai_queue.inc");

// Ensure we don't run multiple instances
$pidfile = "/var/run/ai_log_collector.pid";
if (file_exists($pidfile)) {
    $pid = trim(file_get_contents($pidfile));
    if (is_numeric($pid) && posix_kill($pid, 0)) {
        die("AI Log Collector is already running (PID $pid)\n");
    }
}
file_put_contents($pidfile, getmypid());

// Signal handling
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, 'signal_handler');
    pcntl_signal(SIGINT, 'signal_handler');
}

$running = true;
function signal_handler($signo)
{
    global $running;
    $running = false;
}

// Log files to monitor
$logs = [
    '/var/log/filter.log',
    '/var/log/suricata/eve.json',
    '/var/log/snort/alert',
    '/var/log/ai_honeypot.log'
];

$valid_logs = [];
foreach ($logs as $l) {
    if (file_exists($l))
        $valid_logs[] = $l;
}

if (empty($valid_logs)) {
    // Retry once after delay
    sleep(10);
    foreach ($logs as $l) {
        if (file_exists($l))
            $valid_logs[] = $l;
    }
    if (empty($valid_logs)) {
        @unlink($pidfile);
        exit(0);
    }
}

// Open pipe to tail
$cmd = "tail -n 0 -F " . implode(" ", array_map('escapeshellarg', $valid_logs));
$handle = popen($cmd, "r");

$ip_cache = []; // [ip => timestamp]
$queue = null;

try {
    $queue = new AIQueue();
} catch (Exception $e) {
    die("Failed to initialize Queue: " . $e->getMessage());
}

while ($running && !feof($handle)) {
    $line = fgets($handle);
    if ($line === false)
        break;
    $line = trim($line);
    if (empty($line))
        continue;

    // Quick parse for IP
    $ips = [];
    if (preg_match_all('/(?<![\d.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![\d.])/', $line, $matches)) {
        $ips = $matches[0];
    }

    if (empty($ips))
        continue;

    $target_ip = null;
    foreach ($ips as $ip) {
        if (!is_public($ip))
            continue;

        // Dedup cache (10 seconds)
        if (isset($ip_cache[$ip]) && (time() - $ip_cache[$ip] < 10))
            continue;

        $target_ip = $ip;
        $ip_cache[$ip] = time(); // Update cache
        break; // Only one IP per line to avoid flooding
    }

    if ($target_ip) {
        $queue->push($target_ip, $line);

        // Cleanup cache occasionally
        if (count($ip_cache) > 1000) {
            $now = time();
            foreach ($ip_cache as $k => $v) {
                if ($now - $v > 60)
                    unset($ip_cache[$k]);
            }
        }
    }
}

pclose($handle);
@unlink($pidfile);

function is_public($ip)
{
    if (substr($ip, 0, 4) === '127.')
        return false;
    if (substr($ip, 0, 3) === '10.')
        return false;
    if (substr($ip, 0, 8) === '192.168.')
        return false;
    return true;
}
?>