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