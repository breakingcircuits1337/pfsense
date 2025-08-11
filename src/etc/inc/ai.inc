&lt;?php
/*
 * ai.inc
 * pfSense AI Assistant &amp; Threat Analysis - Provider abstraction (foundation)
 */

/**
 * Abstract base for AI providers.
 */
abstract class AIProvider {
    /**
     * Sends a chat message or array of messages to the provider.
     * @param string|array $messages Array of [{role,content}] or string.
     * @return string Provider's reply.
     */
    abstract public function send_chat($messages);

    /**
     * Fetch API key from config or environment.
     */
    protected function get_config_key($provider, $default_env) {
        global $config;
        $key = $config['system']['ai'][$provider]['apikey'] ?? getenv($default_env);
        if (empty($key)) {
            throw new Exception("API key for $provider not set");
        }
        return $key;
    }

    /**
     * Converts messages (string, array of string, or [{role,content}]) to a single string.
     * Robust handling for LLM chat APIs and freeform text.
     */
    protected function join_messages($messages) {
        // If already a string, return as-is
        if (is_string($messages)) {
            return $messages;
        }
        // If array of messages
        if (is_array($messages)) {
            // Array of [{role, content}]
            if (isset($messages[0]['role']) && isset($messages[0]['content'])) {
                $parts = [];
                foreach ($messages as $msg) {
                    $role = strtoupper($msg['role']);
                    $parts[] = "[$role] " . $msg['content'];
                }
                return implode("\n", $parts);
            }
            // Array of string
            foreach ($messages as $m) {
                if (!is_string($m)) return json_encode($messages);
            }
            return implode(" ", $messages);
        }
        // Fallback: JSON encode
        return json_encode($messages);
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

class ProviderOllama extends AIProvider {
    protected $model;
    protected $host;
    public function __construct() {
        global $config;
        $this->model = $config['system']['ai']['ollama']['model'] ?? getenv('OLLAMA_MODEL') ?? 'llama3.1:8b';
        $this->host = $config['system']['ai']['ollama']['host'] ?? getenv('OLLAMA_HOST') ?? '127.0.0.1';
    }
    /**
     * Send chat to local Ollama server (http://host:11434/api/chat)
     * Accepts array of [{role,content}] or string.
     */
    public function send_chat($messages) {
        $model = $this->model;
        $host = $this->host;
        $url = "http://{$host}:11434/api/chat";
        $timeout = 20;
        // Accepts OpenAI-style messages or string.
        if (is_string($messages)) {
            $messages = [ [ "role" => "user", "content" => $messages ] ];
        } elseif (is_array($messages) && isset($messages[0]) && is_string($messages[0])) {
            $messages = [ [ "role" => "user", "content" => implode(" ", $messages) ] ];
        } elseif (is_array($messages) && isset($messages[0]['role']) && isset($messages[0]['content'])) {
            // Already [{role,content}]
        } else {
            // Fallback: flatten
            $messages = [ [ "role" => "user", "content" => $this->join_messages($messages) ] ];
        }
        $payload = json_encode([
            "model" => $model,
            "messages" => $messages
        ]);
        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl, CURLOPT_POSTFIELDS, $payload);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);
        curl_setopt($curl, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json'
        ]);
        $response = curl_exec($curl);
        if ($response === false) {
            $err = curl_error($curl);
            curl_close($curl);
            throw new Exception("Ollama API unreachable at $url: $err");
        }
        $code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);
        $data = @json_decode($response, true);
        if ($code !== 200 || !$data) {
            throw new Exception("Ollama API failed: HTTP $code, Response: $response");
        }
        // Ollama returns 'message' key with 'content'
        if (isset($data['message']['content'])) {
            return $data['message']['content'];
        }
        throw new Exception("Ollama: Invalid API response");
    }
}

class AIProviderFactory {
    /**
     * Make a provider by name.
     */
    public static function make($provider_name) {
        switch (strtolower($provider_name)) {
            case "gemini":
                return new ProviderGemini();
            case "mistral":
                return new ProviderMistral();
            case "groq":
                return new ProviderGroq();
            case "ollama":
                return new ProviderOllama();
            default:
                throw new Exception("Unknown AI provider: $provider_name");
        }
    }

    /**
     * Pick provider based on config, env, or fallback order.
     * Order: $config['system']['ai']['default_provider'], env AI_PROVIDER, ollama if available, else groq.
     */
    public static function from_config() {
        global $config;
        $provider = $config['system']['ai']['default_provider']
            ?? getenv('AI_PROVIDER')
            ?? null;

        if ($provider) {
            try {
                return self::make($provider);
            } catch (\Exception $e) {
                // Continue to fallback
            }
        }
        // Prefer Ollama if reachable
        try {
            // Health check using config/env, don't access protected property
            $host = AIProvider::get_config_value('system/ai/ollama/host', getenv('OLLAMA_HOST') ?: '127.0.0.1');
            $ch = curl_init("http://{$host}:11434/api/tags");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_TIMEOUT, 2);
            $tags = curl_exec($ch);
            $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            if ($http === 200 && $tags !== false) {
                return new ProviderOllama();
            }
        } catch (\Exception $e) {
            // Ignore Ollama failure
        }
        // Fallback to Groq
        return new ProviderGroq();
    }
}