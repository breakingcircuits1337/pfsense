&lt;?php
/*
 * /api/ai_chat.php
 * Lightweight AI chat endpoint for pfSense AI Assistant
 */
header('Content-Type: application/json');
require_once("../guiconfig.inc");
require_once("/etc/inc/ai.inc");
require_once("/etc/inc/ids.inc");

$config_ai = $config['system']['ai'] ?? [];
$provider_name = $config_ai['default_provider'] ?? 'gemini';

function is_valid_sid($sid) {
    return is_numeric($sid) && $sid > 0 && $sid < 1000000000;
}

try {
    $provider = AIProviderFactory::make($provider_name);
    $input = json_decode(file_get_contents("php://input"), true);
    $user_msg = $input['message'] ?? '';
    $system_prompt = !empty($input['system']) ? $input['system'] : '';
    $messages = $system_prompt ? [$system_prompt, $user_msg] : [$user_msg];
    $reply = $provider->send_chat($messages);

    $json = json_decode(trim($reply), true);
    $result = ['reply' => $reply, 'action' => null, 'success' => false, 'message' => null];
    if (
        is_array($json) &&
        isset($json['target']) &&
        in_array(strtolower($json['target']), ['snort','suricata']) &&
        isset($json['action'])
    ) {
        $target = strtolower($json['target']);
        $sid = $json['sid'] ?? null;
        $action = strtolower($json['action']);
        $msg = isset($json['message']) ? $json['message'] : '';
        if (!is_valid_sid($sid)) throw new Exception("Invalid SID value");
        if ($action === 'disable') {
            ids_disable_sid($target, $sid);
            $result['reply'] = "Disabled rule SID $sid in $target. $msg";
            $result['action'] = "disable";
            $result['success'] = true;
        } elseif ($action === 'enable') {
            ids_enable_sid($target, $sid);
            $result['reply'] = "Enabled rule SID $sid in $target. $msg";
            $result['action'] = "enable";
            $result['success'] = true;
        } elseif ($action === 'add' && isset($json['rule'])) {
            $ruletext = $json['rule'];
            if (strlen($ruletext) > 1024) throw new Exception("Rule text too long");
            if (!preg_match('/sid\s*:\s*'.$sid.'/', $ruletext)) throw new Exception("SID missing from rule text");
            $ok = ids_add_rule($target, $sid, $ruletext);
            if ($ok) {
                $result['reply'] = "Added custom rule SID $sid to $target. $msg";
                $result['action'] = "add";
                $result['success'] = true;
            } else {
                $result['reply'] = "SID $sid already exists in $target custom rules.";
                $result['action'] = "add";
                $result['success'] = false;
            }
        } else {
            throw new Exception("Unrecognised IDS action");
        }
    }
    echo json_encode($result);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['reply' => '[AI error: ' . $e->getMessage() . ']']);
}