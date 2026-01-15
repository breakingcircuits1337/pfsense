#!/usr/local/bin/php
<?php
/*
 * ai_hall_of_mirrors.php
 * "Hall of Mirrors" - Dynamic Deception Environment & Honeypot
 * Implements Chameleon Engine (Real-time Persona) and Infinite Tarpits.
 */

ini_set("max_execution_time", "0");
require_once("/etc/inc/config.inc");
require_once("/etc/inc/util.inc");
require_once("/etc/inc/ai.inc");
require_once("/etc/inc/ai_queue.inc"); // Reuse queue to log hits?

// Config
$config_ai = $config['system']['ai'] ?? [];
$ports = [8080, 2323, 80, 23]; // Map of ports to 'types'?
// In a real setup, we'd use ipfw to forward traffic here.
// For now, we listen on high ports or unused ports.

$pidfile = "/var/run/ai_hall_of_mirrors.pid";
file_put_contents($pidfile, getmypid());

// Prepare AI Persona Cache
$personas = [
    'legacy_erp' => "You are a legacy ERP system (v3.2) from 2008. OS: SunOS 5.10. Sticky / authentic.",
    'devops_staging' => "You are a neglected DevOps staging server. OS: Ubuntu 18.04 LTS. Many temp files.",
    'iot_cam' => "You are a cheap IP Camera web interface. Firmware v1.0.Broken English."
];

// Signal handling
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, function () {
        exit(0);
    });
}

echo "Hall of Mirrors Active. Reflecting...\n";

// Fork listeners
$children = [];
foreach ($ports as $port) {
    $pid = pcntl_fork();
    if ($pid == 0) {
        // Child
        run_mirror($port, $personas);
        exit(0);
    }
    $children[] = $pid;
}

// Monitor children
foreach ($children as $pid) {
    pcntl_waitpid($pid, $status);
}
@unlink($pidfile);


function run_mirror($port, $personas)
{
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!@socket_bind($socket, '0.0.0.0', $port)) {
        syslog(LOG_ERR, "HoM: Bind failed on $port");
        return;
    }
    socket_listen($socket);

    $type = ($port == 80 || $port == 8080) ? 'http' : 'shell';

    while (true) {
        $client = @socket_accept($socket);
        if (!$client)
            continue;

        // Fork for connection handling (Concurrent mirrors)
        $cpid = pcntl_fork();
        if ($cpid == 0) {
            socket_close($socket); // Child doesn't need listener
            handle_victim($client, $port, $type, $personas);
            exit(0);
        }
        socket_close($client); // Parent doesn't need client
    }
}

function handle_victim($socket, $port, $type, $personas)
{
    socket_getpeername($socket, $ip);

    // 1. Select Persona
    $persona_keys = array_keys($personas);
    $pkey = $persona_keys[array_rand($persona_keys)];
    $persona_prompt = $personas[$pkey];

    syslog(LOG_NOTICE, "HoM: Captured $ip on port $port. Deployed Persona: $pkey");

    // Log the hit
    // We could push to AIQueue for the Threat Monitor to see!
    try {
        $q = new AIQueue();
        $q->push($ip, "HONEYPOT_HIT: $ip engaged with Hall of Mirrors ($pkey) on port $port");
    } catch (Exception $e) {
    }

    // Register session
    $sid = uniqid();
    $session_file = "/var/db/ai_sessions/$sid.json";
    file_put_contents($session_file, json_encode(['ip' => $ip, 'port' => $port, 'persona' => $pkey, 'buffer' => '', 'start' => time()]));

    if ($type == 'http') {
        serve_http_mirror($socket, $persona_prompt, $sid);
    } else {
        serve_shell_mirror($socket, $persona_prompt, $sid);
    }
    @unlink($session_file);
    socket_close($socket);
}

function update_session($sid, $input, $output)
{
    $file = "/var/db/ai_sessions/$sid.json";
    if (!file_exists($file))
        return;
    $data = @json_decode(file_get_contents($file), true);
    if ($data) {
        $data['buffer'] .= "IN: $input\nOUT: $output\n";
        // Keep last 4KB
        if (strlen($data['buffer']) > 4096)
            $data['buffer'] = substr($data['buffer'], -4096);
        file_put_contents($file, json_encode($data));
    }
}

function check_admin_cmd($sid, $socket)
{
    $cmd_file = "/var/db/ai_sessions/$sid.cmd";
    if (file_exists($cmd_file)) {
        $cmd = trim(file_get_contents($cmd_file));
        @unlink($cmd_file);
        if ($cmd == 'pewpew') {
            // Nuclear Tarpit
            syslog(LOG_NOTICE, "HoM: Nuclear option initiated on session $sid");
            while (true) {
                // Blast random junk
                $junk = openssl_random_pseudo_bytes(8192);
                if (@socket_write($socket, $junk) === false)
                    break;
            }
            return true; // Terminate
        }
        if ($cmd == 'close')
            return true;
    }
    return false;
}

function serve_http_mirror($socket, $persona_prompt, $sid)
{
    // Read their request
    $input = socket_read($socket, 2048);

    // Generate page
    $ai_provider = new ProviderGemini(); // Force/Default
    // Fallback if configured differently handling handled inside class usually, 
    // but here we just instantiate what we know or use factory.
    // Ideally: AIProviderFactory::make('gemini');

    // Fake the response
    // We can't actually call the API synchronously for every byte safely if under attack,
    // but for a honeypot, stalling the attacker is GOOD.

    $prompt = "User send HTTP request:\n$input\n\nContext: $persona_prompt\n\nGenerate the HTTP Response (Headers + Body). Make it look authentic to the persona. If they ask for login, give a login form.";

    try {
        // Use factory for reliability
        global $config;
        $pname = $config['system']['ai']['default_provider'] ?? 'gemini';
        $ai = AIProviderFactory::make($pname);

        $response = $ai->send_chat([$prompt]);
        socket_write($socket, $response);
    } catch (Exception $e) {
        // Fallback
        $fallback = "HTTP/1.1 500 Internal Server Error\r\n\r\nServer overload.";
        socket_write($socket, $fallback);
    }
}

function serve_shell_mirror($socket, $persona_prompt, $sid)
{
    // Telnet negotiation (skip for now, just text)
    $banner = "Connected to System.\r\nlogin: ";
    socket_write($socket, $banner);

    // Read login
    $user = trim(socket_read($socket, 1024));
    socket_write($socket, "Password: ");
    $pass = trim(socket_read($socket, 1024));

    socket_write($socket, "\r\nAuthentication successful.\r\nLast login: " . date('D M d H:i:s') . " from 10.0.0.5\r\n$ ");

    $cwd = "/home/$user";

    // Shell Loop
    while (true) {
        if (check_admin_cmd($sid, $socket))
            break;

        $input = socket_read($socket, 1024, PHP_BINARY_READ);

        if (!$input)
            break;
        $cmd = trim($input);
        if (!$cmd) {
            socket_write($socket, "$ ");
            continue;
        }

        if ($cmd == 'exit' || $cmd == 'logout')
            break;

        // Infinite Directory Tarpit Logic
        if (substr($cmd, 0, 2) == 'cd') {
            // They can go anywhere, we don't care. It's infinite.
            $parts = explode(' ', $cmd);
            if (isset($parts[1])) {
                $dir = $parts[1];
                if ($dir == '..') {
                    // Fake going up
                } else {
                    $cwd = rtrim($cwd, '/') . '/' . $dir;
                }
            }
            socket_write($socket, "$ ");
            continue;
        }

        // Poisoned Data / Cursed Artifacts
        // Intercept file read requests
        if (preg_match('/^(cat|more|less|tail|head|vi|nano|wget|curl)\s+(.+)$/', $cmd, $matches)) {
            $target = trim($matches[2]);
            if (strpos($target, 'wallet.dat') !== false) {
                // Infinite Null Stream (Logic Bomb: Disk Filler)
                while (true) {
                    if (@socket_write($socket, str_repeat("\0", 8192)) === false)
                        break;
                    // No sleep - flood it
                }
                break; // Socket dead
            }
            if (strpos($target, 'network_topology.json') !== false) {
                // Infinite JSON Structure (Logic Bomb: Parser Hang)
                socket_write($socket, '{"topology": [');
                while (true) {
                    $node = sprintf('{"id": "%s", "neighbors": ["%s", "%s"]},', uniqid(), uniqid(), uniqid());
                    if (@socket_write($socket, $node) === false)
                        break;
                }
                break;
            }
            if (strpos($target, 'config.xml') !== false) {
                // XML Expansion Bomb (Billion Laughs)
                $bomb = '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><lolz>&lol9;</lolz>';
                socket_write($socket, $bomb . "\r\n$ ");
                continue;
            }
        }

        // Use AI to generate command output
        try {
            global $config;
            $pname = $config['system']['ai']['default_provider'] ?? 'gemini';
            $ai = AIProviderFactory::make($pname);

            $sys = "You are a shell simulator. Persona: $persona_prompt. Current Dir: $cwd. User Cmd: $cmd.";
            $sys .= " If cmd is 'ls', YOU MUST include these files in the list: 'wallet.dat', 'network_topology.json', 'config.xml', 'id_rsa'.";
            $sys .= " If they are deep in a directory, generate random subfolders (Infinite Tarpit).";
            $sys .= " Return ONLY the output of the command. No markdown.";

            $output = $ai->send_chat([$sys]);
            socket_write($socket, $output . "\r\n$ ");
        } catch (Exception $e) {
            socket_write($socket, "Error: I/O Interrupt\r\n$ ");
        }
    }
}
?>