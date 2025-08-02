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