&lt;?php
/*
 * ai.inc
 * pfSense AI Assistant &amp; Threat Analysis - Provider abstraction (foundation)
 */

abstract class AIProvider {
    abstract public function send_chat($messages);
    protected function get_config_key($provider, $default_env) {
        global $config;
        $key = $config['system']['ai'][$provider]['apikey'] ?? getenv($default_env);
        if (empty($key)) {
            throw new Exception("API key for $provider not set");
        }
        return $key;
    }
    protected function join_messages($messages) {
        return is_array($messages) ? implode(" ", $messages) : strval($messages);
    }
    // Helper for config with fallback/default
    public static function get_config_value($path, $default = null) {
        global $config;
        $node = $config;
        foreach (explode('/', $path) as $seg) {
            if (!is_array($node) || !array_key_exists($seg, $node)) {
                return $default;
            }
            $node = $node[$seg];
        }
        return $node;
    }

    // Returns: [ 'enabled'=>bool, 'threshold'=>float, 'ttl'=>int ]
    public static function get_ai_policy($if = null, $rule = null) {
        global $config;
        $mon = $config['system']['ai']['monitor'] ?? [];
        $res = [
            'enabled' => true,
            'threshold' => isset($mon['threshold']) ? floatval($mon['threshold']) : 0.7,
            'ttl'      => isset($mon['block_ttl_hours']) ? intval($mon['block_ttl_hours']) : 24,
        ];
        // interface override
        if ($if && isset($mon['interfaces'][$if])) {
            $intf = $mon['interfaces'][$if];
            if (array_key_exists('enable', $intf)) $res['enabled'] = !!$intf['enable'];
            if (isset($intf['threshold']) && $intf['threshold'] !== '') $res['threshold'] = floatval($intf['threshold']);
            if (isset($intf['ttl']) && $intf['ttl'] !== '') $res['ttl'] = intval($intf['ttl']);
        }
        // rule override (wins)
        if ($rule && isset($mon['rules'][$rule])) {
            $r = $mon['rules'][$rule];
            if (array_key_exists('enable', $r)) $res['enabled'] = !!$r['enable'];
            if (isset($r['threshold']) && $r['threshold'] !== '') $res['threshold'] = floatval($r['threshold']);
            if (isset($r['ttl']) && $r['ttl'] !== '') $res['ttl'] = intval($r['ttl']);
        }
        return $res;
    }

    public static function policy_enabled($if = null, $rule = null) {
        $p = self::get_ai_policy($if, $rule);
        return !empty($p['enabled']);
    }
}

class ProviderGemini extends AIProvider {
    protected $model;
    public function __construct() {
        global $config;
        $this->model = $config['system']['ai']['gemini']['model'] ?? 'gemini-pro';
    }
    public function send_chat($messages) {
        $key = $this->get_config_key('gemini', 'AI_GEMINI_KEY');
        $joined = $this->join_messages($messages);
        $url = "https://generativelanguage.googleapis.com/v1beta/models/{$this->model}:generateContent?key=" . urlencode($key);
        $payload = json_encode([
            "contents" => [
                [ "parts" => [ [ "text" => $joined ] ] ]
            ]
        ]);
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        $response = curl_exec($curl);
        if ($response === false) {
            throw new Exception("Gemini API error: " . curl_error($curl));
        }
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        $data = @json_decode($response, true);
        if ($code !== 200 || !$data) {
            throw new Exception("Gemini API failed: HTTP $code, Response: $response");
        }
        // Pick contents[0].candidates[0].content.parts[0].text as reply.
        if (isset($data['candidates'][0]['content']['parts'][0]['text'])) {
            return $data['candidates'][0]['content']['parts'][0]['text'];
        }
        throw new Exception("Gemini: Invalid API response");
    }
}

class ProviderMistral extends AIProvider {
    protected $model;
    public function __construct() {
        global $config;
        $this->model = $config['system']['ai']['mistral']['model'] ?? 'mistral-tiny';
    }
    public function send_chat($messages) {
        $key = $this->get_config_key('mistral', 'AI_MISTRAL_KEY');
        $joined = $this->join_messages($messages);
        $url = "https://api.mistral.ai/v1/chat/completions";
        $payload = json_encode([
            "model" => $this->model,
            "messages" => [
                [ "role" => "user", "content" => $joined ]
            ]
        ]);
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            "Authorization: Bearer $key"
        ]);
        $response = curl_exec($curl);
        if ($response === false) {
            throw new Exception("Mistral API error: " . curl_error($curl));
        }
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        $data = @json_decode($response, true);
        if ($code !== 200 || !$data) {
            throw new Exception("Mistral API failed: HTTP $code, Response: $response");
        }
        // choices[0].message.content
        if (isset($data['choices'][0]['message']['content'])) {
            return $data['choices'][0]['message']['content'];
        }
        throw new Exception("Mistral: Invalid API response");
    }
}

class ProviderGroq extends AIProvider {
    protected $model;
    public function __construct() {
        global $config;
        $this->model = $config['system']['ai']['groq']['model'] ?? 'mixtral-8x7b-32768';
    }
    public function send_chat($messages) {
        $key = $this->get_config_key('groq', 'AI_GROQ_KEY');
        $joined = $this->join_messages($messages);
        $url = "https://api.groq.com/openai/v1/chat/completions";
        $payload = json_encode([
            "model" => $this->model,
            "messages" => [
                [ "role" => "user", "content" => $joined ]
            ]
        ]);
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 15);
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            "Authorization: Bearer $key"
        ]);
        $response = curl_exec($curl);
        if ($response === false) {
            throw new Exception("Groq API error: " . curl_error($curl));
        }
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        $data = @json_decode($response, true);
        if ($code !== 200 || !$data) {
            throw new Exception("Groq API failed: HTTP $code, Response: $response");
        }
        // choices[0].message.content
        if (isset($data['choices'][0]['message']['content'])) {
            return $data['choices'][0]['message']['content'];
        }
        throw new Exception("Groq: Invalid API response");
    }
}

class AIProviderFactory {
    public static function make($provider_name) {
        switch (strtolower($provider_name)) {
            case "gemini":
                return new ProviderGemini();
            case "mistral":
                return new ProviderMistral();
            case "groq":
                return new ProviderGroq();
            default:
                throw new Exception("Unknown AI provider: $provider_name");
        }
    }
}

function ai_get_system_context() {
    global $config;
    $context = [];

    // Interfaces
    $if_strs = [];
    if (isset($config['interfaces'])) {
        foreach ($config['interfaces'] as $ifname => $ifdata) {
            $descr = isset($ifdata['descr']) ? $ifdata['descr'] : strtoupper($ifname);
            $ip = isset($ifdata['ipaddr']) ? $ifdata['ipaddr'] : 'n/a';
            $if_strs[] = "$descr ($ifname) [$ip]";
        }
    }
    $context[] = "Interfaces: " . implode(", ", $if_strs);

    // Aliases
    $alias_strs = [];
    if (isset($config['aliases']['alias']) && is_array($config['aliases']['alias'])) {
        foreach ($config['aliases']['alias'] as $a) {
             $alias_strs[] = $a['name'] . "(" . $a['type'] . ")";
        }
    }
    if ($alias_strs) {
        $context[] = "Aliases: " . implode(", ", $alias_strs);
    }

    // Rule Summary
    if (isset($config['filter']['rule']) && is_array($config['filter']['rule'])) {
        $context[] = "Active Rules: " . count($config['filter']['rule']) . " defined.";
    }

    return implode("\n", $context);
}