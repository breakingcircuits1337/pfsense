#!/usr/local/bin/php
<?php
/*
 * ai_agent_inquisitor.php
 * "The Inquisitor" - IDS/IPS Analyst
 */

require_once("/etc/inc/agents.inc");

class InquisitorAgent extends AIAgent {
    private $suricata_log = '/var/log/suricata/eve.json';

    public function __construct() {
        parent::__construct("Inquisitor", "The investigator. Process IDS alerts, prune false positives, and model intent.");
    }

    public function observe() {
        // Discover Suricata log file if not set or invalid
        if (!file_exists($this->suricata_log)) {
            $candidates = glob('/var/log/suricata/*/eve.json');
            if ($candidates && count($candidates) > 0) {
                // Pick the most recently modified one
                usort($candidates, function($a, $b) { return filemtime($b) - filemtime($a); });
                $this->suricata_log = $candidates[0];
            }
        }

        if (!file_exists($this->suricata_log)) return;

        // Read new Suricata alerts safely
        $cmd = "tail -n 20 " . escapeshellarg($this->suricata_log);
        exec($cmd, $lines);

        foreach ($lines as $line) {
            $alert = json_decode($line, true);
            if ($alert && isset($alert['event_type']) && $alert['event_type'] === 'alert') {
                $sig_id = $alert['alert']['signature_id'];
                // Check if we've analyzed this signature recently to avoid spam
                if (!isset($this->memory['analyzed_sigs'][$sig_id]) || (time() - $this->memory['analyzed_sigs'][$sig_id] > 3600)) {
                    $this->memory['pending_alerts'][] = $alert;
                    $this->memory['analyzed_sigs'][$sig_id] = time();
                }
            }
        }
    }

    public function analyze() {
        $alerts = $this->memory['pending_alerts'] ?? [];
        if (empty($alerts)) return;

        foreach ($alerts as $alert) {
            $sig = $alert['alert']['signature'];
            $src = $alert['src_ip'];
            $dest_port = $alert['dest_port'];

            // "False Positive Pruning" & "Intent Modeling"
            $decision = $this->ask_ai(
                "Analyze this IDS alert. Is it likely a False Positive given the context (e.g. common background noise)? Or is it a high-intent targeted attack? Return JSON: {\"verdict\": \"real\"|\"noise\", \"severity\": \"high\"|\"low\", \"reason\": \"...\"}",
                "Alert: $sig. Source: $src. Target Port: $dest_port."
            );

            $json = $this->extract_json($decision);
            if ($json) {
                if ($json['verdict'] === 'real' && $json['severity'] === 'high') {
                    $this->memory['escalations'][] = ['ip' => $src, 'reason' => $json['reason'] . " (Sig: $sig)"];
                } else {
                    $this->log("Pruned False Positive/Noise: $sig from $src");
                }
            }
        }
        $this->memory['pending_alerts'] = [];
    }

    public function act() {
        if (!empty($this->memory['escalations'])) {
            foreach ($this->memory['escalations'] as $esc) {
                $this->log("Contextual Escalation: Blocking {$esc['ip']}. Reason: {$esc['reason']}");
                // Hand off to Gatekeeper (via shared blocklist)
                mwexec("/sbin/pfctl -t ai_blocklist -T add " . escapeshellarg($esc['ip']));

                // Add to event log for Gatekeeper 6th sense
                $log_entry = json_encode(['type' => 'escalation', 'ip' => $esc['ip'], 'reason' => $esc['reason'], 'timestamp' => time()]);
                file_put_contents('/var/db/ai_events.log', $log_entry . "\n", FILE_APPEND);
            }
            $this->memory['escalations'] = [];
        }
    }

    private function extract_json($text) {
        if (preg_match('/\{.*\}/s', $text, $matches)) {
            return json_decode($matches[0], true);
        }
        return null;
    }
}

// Daemon Run Loop
$agent = new InquisitorAgent();
echo "Starting The Inquisitor...\n";
while (true) {
    $agent->run_cycle();
    sleep(15); // Fast loop
}
?>
