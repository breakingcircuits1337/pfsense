&lt;?php
/*
 * /api/ai_chat.php
 * Lightweight AI chat endpoint for pfSense AI Assistant
 */
header('Content-Type: application/json');
require_once("../guiconfig.inc");
require_once("/etc/inc/ai.inc");

$config_ai = $config['system']['ai'] ?? [];
$provider_name = $config_ai['default_provider'] ?? 'gemini';

try {
    $provider = AIProviderFactory::make($provider_name);
    $input = json_decode(file_get_contents("php://input"), true);
    $user_msg = $input['message'] ?? '';
    $reply = $provider->send_chat([$user_msg]);
    echo json_encode(['reply' => $reply]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['reply' => '[AI error: ' . $e->getMessage() . ']']);
}