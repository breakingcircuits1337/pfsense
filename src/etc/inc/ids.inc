<?php
/*
 * ids.inc
 * pfSense IDS/IPS Helper Library for AI
 * BSD (c) 2024 The pfSense Contributors
 */

require_once("/etc/inc/util.inc");

function ids_list_instances($type) {
	$base = "/usr/local/etc/{$type}/";
	if (!is_dir($base)) return [];
	$out = [];
	foreach (scandir($base) as $file) {
		if (preg_match("/^{$type}_(.+)$/", $file, $m)) {
			$out[] = $file;
		}
	}
	return $out;
}

function ids_disable_sid($type, $sid) {
	$instances = ids_list_instances($type);
	foreach ($instances as $uuid) {
		$cmd = "/usr/local/bin/{$type}_control ".escapeshellarg($uuid)." disable_sid ".escapeshellarg($sid);
		mwexec($cmd);
	}
}
function ids_enable_sid($type, $sid) {
	$instances = ids_list_instances($type);
	foreach ($instances as $uuid) {
		$cmd = "/usr/local/bin/{$type}_control ".escapeshellarg($uuid)." enable_sid ".escapeshellarg($sid);
		mwexec($cmd);
	}
}
function ids_add_rule($type, $sid, $rule) {
	$dir = "/usr/local/etc/{$type}/rules/";
	if (!is_dir($dir)) mkdir($dir, 0755, true);
	$file = "{$dir}ai_custom.rules";
	// Ensure SID unique in file
	$lines = file_exists($file) ? file($file) : [];
	foreach ($lines as $l) {
		if (preg_match('/sid\s*:\s*'.preg_quote($sid).'/', $l)) {
			return false; // already present
		}
	}
	$rule = trim($rule);
	file_put_contents($file, $rule . "\n", FILE_APPEND);
	ids_reload($type);
	return true;
}
function ids_reload($type) {
	$instances = ids_list_instances($type);
	foreach ($instances as $uuid) {
		$cmd = "/usr/local/bin/{$type}_control ".escapeshellarg($uuid)." restart";
		mwexec($cmd);
	}
}

// Emerging Threats Rule Index helpers
function load_et_index() {
	static $index = null;
	if ($index !== null) return $index;
	$file = '/var/db/et_index.json';
	if (!file_exists($file)) return [];
	$index = @json_decode(file_get_contents($file), true);
	if (!is_array($index)) $index = [];
	return $index;
}
function et_lookup_sid($sid) {
	$rules = load_et_index();
	foreach ($rules as $rule) {
		if ($rule['sid'] == $sid) return $rule;
	}
	return null;
}
// $kw can be space-separated, match any substring in msg, return up to $limit
function et_search_keywords($kw, $limit = 5) {
	$rules = load_et_index();
	if (!$kw) return [];
	$kw = strtolower($kw);
	$results = [];
	foreach ($rules as $rule) {
		if (strpos(strtolower($rule['msg']), $kw) !== false) {
			$results[] = ['sid'=>$rule['sid'], 'msg'=>$rule['msg']];
			if (count($results) >= $limit) break;
		}
	}
	return $results;
}

// Log AI-driven IDS rule changes
function ids_log_change($type, $action, $sid, $details = '') {
	$logfile = '/var/db/ai_rule_changes.log';
	$rec = [
		'ts' => date('c'),
		'engine' => $type,
		'action' => $action,
		'sid' => $sid,
		'info' => $details,
	];
	file_put_contents($logfile, json_encode($rec) . "\n", FILE_APPEND);
	// Truncate if >1MB, keep last 500 lines
	if (file_exists($logfile) && filesize($logfile) > 1024*1024) {
		$lines = file($logfile);
		$lines = array_slice($lines, -500);
		file_put_contents($logfile, implode("", $lines));
	}
}