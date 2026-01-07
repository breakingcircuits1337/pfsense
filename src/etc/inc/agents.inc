<?php
/*
 * agents.inc
 * Base Framework for Autonomous AI Agents in BC's PFnonsense
 */

require_once("/etc/inc/ai.inc");
require_once("/etc/inc/util.inc");

abstract class AIAgent {
    protected $name;
    protected $description;
    protected $config;
    protected $memory_file;
    protected $memory = [];
    protected $enabled = false;

    public function __construct($name, $description) {
        global $config;
        $this->name = $name;
        $this->description = $description;
        $this->config = $config['system']['ai']['agents'][strtolower($name)] ?? [];
        $this->enabled = !empty($this->config['enable']);
        $this->memory_file = "/var/db/ai_agent_" . strtolower($name) . ".json";
        $this->load_memory();
    }

    protected function load_memory() {
        if (file_exists($this->memory_file)) {
            $data = json_decode(file_get_contents($this->memory_file), true);
            if (is_array($data)) $this->memory = $data;
        }
    }

    protected function save_memory() {
        file_put_contents($this->memory_file, json_encode($this->memory, JSON_PRETTY_PRINT));
    }

    protected function log($msg, $level = LOG_NOTICE) {
        $log_msg = "[{$this->name}] $msg";
        syslog($level, $log_msg);
        echo date('Y-m-d H:i:s') . " $log_msg\n";
    }

    protected function ask_ai($system_prompt, $user_message, $context = []) {
        try {
            // Respect global provider settings
            global $config;
            $provider_name = $config['system']['ai']['default_provider'] ?? 'gemini';
            $provider = AIProviderFactory::make($provider_name);

            $full_system = "You are '{$this->name}', an autonomous security agent on a firewall. " .
                           "Role: {$this->description}. " .
                           $system_prompt;

            if (!empty($context)) {
                $user_message .= "\n\nContext:\n" . json_encode($context);
            }

            return $provider->send_chat([$full_system, $user_message]);
        } catch (Exception $e) {
            $this->log("AI Error: " . $e->getMessage(), LOG_ERR);
            return null;
        }
    }

    // Core Loop Methods
    abstract public function observe();  // Gather data (logs, state, config)
    abstract public function analyze();  // Process data (locally or via LLM)
    abstract public function act();      // Execute changes (pfctl, service restart, etc.)

    public function run_cycle() {
        if (!$this->enabled) return;
        $this->observe();
        $this->analyze();
        $this->act();
        $this->save_memory();
    }
}
?>
