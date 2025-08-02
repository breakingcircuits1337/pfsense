#!/usr/local/bin/php
<?php
/*
 * et_index.php
 * Emerging Threats Rule Indexer for pfSense AI Assistant
 * BSD (c) 2024 The pfSense Contributors
 */
$targets = ['snort', 'suricata'];
$rules = [];
foreach ($targets as $engine) {
    $dir = "/usr/local/etc/$engine/rules";
    if (!is_dir($dir)) continue;
    foreach (glob("$dir/emerging*.rules") as $file) {
        $lines = file($file);
        foreach ($lines as $line) {
            if (preg_match('/\b(alert|drop)\b.*sid:(\d+);.*msg:"([^"]+)/i', $line, $m)) {
                $rules[] = [
                    'sid' => intval($m[2]),
                    'msg' => $m[3],
                    'file' => basename($file)
                ];
            }
        }
    }
}
file_put_contents('/var/db/et_index.json', json_encode($rules));