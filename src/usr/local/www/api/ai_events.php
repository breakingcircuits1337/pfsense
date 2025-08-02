<?php
/*
 * /api/ai_events.php
 * SSE event stream for AI block/unblock
 */
set_time_limit(0);
header('Content-Type: text/event-stream');
header('Cache-Control: no-cache');
header('Connection: keep-alive');

$blocklist = '/var/db/ai_blocklist.json';
$events = '/var/db/ai_events.log';

function send_event($event, $data) {
    echo "event: $event\n";
    echo "data: " . json_encode($data) . "\n\n";
    @ob_flush();
    @flush();
}

$last_bl_mtime = file_exists($blocklist) ? filemtime($blocklist) : 0;
$last_ev_size = file_exists($events) ? filesize($events) : 0;

while (true) {
    clearstatcache();
    $bl_mtime = file_exists($blocklist) ? filemtime($blocklist) : 0;
    $ev_size = file_exists($events) ? filesize($events) : 0;

    // Send new block/unblock events
    if ($ev_size > $last_ev_size) {
        $fp = fopen($events, 'r');
        fseek($fp, $last_ev_size);
        while (($line = fgets($fp)) !== false) {
            $json = json_decode(trim($line), true);
            if (!$json) continue;
            if ($json['type'] === 'block') send_event('block', $json);
            if ($json['type'] === 'unblock') send_event('unblock', $json);
        }
        fclose($fp);
        $last_ev_size = $ev_size;
    }

    // If blocklist file changed, send refresh event
    if ($bl_mtime !== $last_bl_mtime) {
        $rows = file_exists($blocklist) ? json_decode(file_get_contents($blocklist), true) : [];
        send_event('refresh', $rows);
        $last_bl_mtime = $bl_mtime;
    }

    sleep(2);
    if (connection_aborted()) exit;
}