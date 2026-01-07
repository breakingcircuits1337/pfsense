<?php
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
    $user_msg = strip_tags($input['message'] ?? ''); // Basic sanitization

    // Security: Only allow system prompts if strictly necessary or sanitize them.
    // For now, we strip tags to prevent HTML injection if this is ever reflected directly,
    // though the main risk is prompt injection which is inherent to LLMs.
    $system_prompt = strip_tags(!empty($input['system']) ? $input['system'] : '');

    // Enforce a hardcoded system instruction if none provided, or append to user provided one to ensure safety
    // Ideally, for a firewall assistant, we should prepend a forceful system instruction.
    $base_system = "You are an intelligent firewall assistant for pfSense. You help manage rules and security.";

    if ($system_prompt) {
        // If the UI sends a system prompt (e.g. for context), we trust it but prepend our base identity.
        $messages = [$base_system . " " . $system_prompt, $user_msg];
    } else {
        $messages = [$base_system, $user_msg];
    }

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
        $action = strtolower($json['action']);
        $msg = isset($json['message']) ? $json['message'] : '';

        // Suggest flow
        if ($action === 'suggest' && isset($json['keyword'])) {
            $kw = $json['keyword'];
            $suggestions = et_search_keywords($kw, 5);
            $result['action'] = "suggest";
            $result['success'] = true;
            $result['suggestions'] = $suggestions;
            if ($suggestions) {
                $txt = "Emerging Threats rules matching \"$kw\":\n";
                foreach ($suggestions as $s) {
                    $txt .= "SID {$s['sid']}: {$s['msg']}\n";
                }
            } else {
                $txt = "No matching Emerging Threats rules found for \"$kw\".";
            }
            $result['reply'] = $txt;
        } else {
            $sid = $json['sid'] ?? null;
            if (!is_valid_sid($sid)) throw new Exception("Invalid SID value");

            if ($action === 'disable') {
                ids_disable_sid($target, $sid);
                ids_log_change($target, "disable", $sid, "Disabled via AI chat");
                $result['reply'] = "Disabled rule SID $sid in $target. $msg";
                $result['action'] = "disable";
                $result['success'] = true;
            } elseif ($action === 'enable') {
                ids_enable_sid($target, $sid);
                ids_log_change($target, "enable", $sid, "Enabled via AI chat");
                $result['reply'] = "Enabled rule SID $sid in $target. $msg";
                $result['action'] = "enable";
                $result['success'] = true;
            } elseif ($action === 'add' && isset($json['rule'])) {
                $ruletext = $json['rule'];
                if (strlen($ruletext) > 1024) throw new Exception("Rule text too long");
                if (!preg_match('/sid\s*:\s*'.$sid.'/', $ruletext)) throw new Exception("SID missing from rule text");
                $ok = ids_add_rule($target, $sid, $ruletext);
                if ($ok) {
                    ids_log_change($target, "add", $sid, "Added via AI chat");
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
    }
    echo json_encode($result);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['reply' => '[AI error: ' . $e->getMessage() . ']']);
}
