#!/usr/local/bin/php
<?php
/*
 * ai_agent_steward.php
 * "The Steward" - Config & Health Guardian Agent
 */

require_once("/etc/inc/agents.inc");
require_once("/etc/inc/config.inc");

class StewardAgent extends AIAgent {
    private $config_path = '/conf/config.xml';
    private $last_hash = '';
    private $pending_analysis = false;

    public function __construct() {
        parent::__construct("Steward", "The immune system of the firewall. Monitor config integrity and service health.");
        $this->last_hash = $this->memory['last_config_hash'] ?? md5_file($this->config_path);
    }

    public function observe() {
        // Check for config drift
        $current_hash = md5_file($this->config_path);
        if ($current_hash !== $this->last_hash) {
            $this->log("Config change detected!");
            $this->memory['last_config_hash'] = $current_hash;
            $this->pending_analysis = true;
        }

        // Check essential services (simplified list)
        $services = ['unbound', 'dpinger', 'sshd', 'pfb_filter']; // Example services
        foreach ($services as $svc) {
            if (!$this->is_service_running($svc)) {
                $this->memory['service_failures'][$svc] = time();
                $this->log("Service $svc is NOT running.");
                $this->pending_analysis = true;
            }
        }
    }

    public function analyze() {
        if (!$this->pending_analysis) return;

        // Config Analysis
        if (isset($this->memory['last_config_hash'])) {
            // Ideally we would diff the XML, but for V1 let's just log/alert
            // or ask AI if this change pattern looks suspicious based on logs (mocked here)
            $this->log("Analyzing config change...");
            $ai_decision = $this->ask_ai(
                "A configuration change was detected. Analyze if this fits a known maintenance window or looks suspicious.",
                "Config hash changed. Current time: " . date('c')
            );
            $this->log("AI Analysis on Config: $ai_decision");
        }

        // Service Healing Analysis
        if (!empty($this->memory['service_failures'])) {
            foreach ($this->memory['service_failures'] as $svc => $ts) {
                // Ask AI for healing strategy
                $log_tail = $this->get_service_logs($svc);
                $advice = $this->ask_ai(
                    "Service '$svc' has failed. Analyze the recent logs and suggest a fix (restart, config tweak, or ignore). Return JSON: {\"action\": \"restart\"|\"ignore\", \"reason\": \"...\"}",
                    "Service Logs:\n$log_tail"
                );

                $json = $this->extract_json($advice);
                if ($json && isset($json['action']) && $json['action'] === 'restart') {
                    $this->memory['healing_actions'][$svc] = 'restart';
                }
            }
        }

        $this->pending_analysis = false;
    }

    public function act() {
        // Execute Healing
        if (!empty($this->memory['healing_actions'])) {
            foreach ($this->memory['healing_actions'] as $svc => $action) {
                if ($action === 'restart') {
                    $this->log("Self-Healing: Restarting $svc...");
                    mwexec("service $svc restart"); // standard FreeBSD service command
                    unset($this->memory['service_failures'][$svc]);
                }
            }
            $this->memory['healing_actions'] = [];
        }
    }

    private function is_service_running($name) {
        // Simple pgrep check
        exec("pgrep -f $name", $output, $return_var);
        return $return_var === 0;
    }

    private function get_service_logs($name) {
        // Mock log retrieval - in real pfSense, check /var/log/system.log
        return shell_exec("tail -n 20 /var/log/system.log | grep $name");
    }

    private function extract_json($text) {
        if (preg_match('/\{.*\}/s', $text, $matches)) {
            return json_decode($matches[0], true);
        }
        return null;
    }
}

// Daemon Run Loop
$agent = new StewardAgent();
echo "Starting The Steward...\n";
while (true) {
    $agent->run_cycle();
    sleep(60); // Run every minute
}
?>
