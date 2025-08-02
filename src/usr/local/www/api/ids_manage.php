<?php
/*
 * ids_manage.php
 * API endpoint for enabling/adding IDS rules (pfSense AI)
 */
require_once("/etc/inc/ids.inc");

header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	http_response_code(405);
	echo json_encode(['success' => false, 'message' => 'POST only']);
	exit;
}
$data = json_decode(file_get_contents("php://input"), true);
$type = strtolower($data['target'] ?? '');
$action = strtolower($data['action'] ?? '');
$sid = $data['sid'] ?? null;
$rule = $data['rule'] ?? null;
if (!in_array($type, ['snort','suricata'])) {
	echo json_encode(['success'=>false,'message'=>'Invalid target']);
	exit;
}
if (!is_numeric($sid) || $sid <= 0 || $sid >= 1000000000) {
	echo json_encode(['success'=>false,'message'=>'Invalid SID']);
	exit;
}
try {
	if ($action === 'enable') {
		ids_enable_sid($type, $sid);
		echo json_encode(['success'=>true,'message'=>"Enabled SID $sid on $type."]);
		exit;
	} elseif ($action === 'add' && $rule) {
		if (strlen($rule) > 1024) throw new Exception("Rule text too long");
		if (!preg_match('/sid\s*:\s*'.$sid.'/', $rule)) throw new Exception("SID missing from rule text");
		$ok = ids_add_rule($type, $sid, $rule);
		if ($ok) {
			echo json_encode(['success'=>true,'message'=>"Added rule SID $sid to $type."]);
		} else {
			echo json_encode(['success'=>false,'message'=>"SID $sid already exists in $type custom rules."]);
		}
		exit;
	} else {
		echo json_encode(['success'=>false,'message'=>'Invalid action or missing rule text.']);
		exit;
	}
} catch (Exception $e) {
	echo json_encode(['success'=>false,'message'=>$e->getMessage()]);
	exit;
}