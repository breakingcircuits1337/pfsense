<?php
/*
 * AI Assistant Dashboard Widget
 * Shows quick links and recent AI Assistant activity (preview-only, never applies).
 */
?>
<style>
#ai-assistant-widget .ai-btns a { margin-right: 0.5em; }
#ai-assistant-widget .ai-recent { margin-top: 0.6em; font-size: 0.98em; }
#ai-assistant-widget .ai-recent-list { list-style: none; padding-left: 0; margin: 0;}
#ai-assistant-widget .ai-recent-list li { margin-bottom: 0.4em; }
#ai-assistant-widget .ai-recent-type { font-weight: bold; margin-right: .4em; }
#ai-assistant-widget .ai-recent-date { color: #888; font-size: 0.92em; margin-right: .4em; }
</style>
<div id="ai-assistant-widget">
  <div class="ai-btns" style="margin-bottom:.7em;">
    <a href="/ai_assistant.php?tab=assistant" class="btn btn-xs btn-info">Open Assistant</a>
    <a href="/ai_assistant.php?tab=analyze" class="btn btn-xs btn-primary">Analyze Rules</a>
    <a href="/ai_assistant.php?tab=wizards" class="btn btn-xs btn-success">Wizards</a>
  </div>
  <div class="ai-recent">
    <b>Recent AI Activity:</b>
    <ul class="ai-recent-list">
<?php
$recent = [];
$logfile = "/tmp/ai_assistant_recent.jsonl";
if (is_readable($logfile)) {
    $lines = @file($logfile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if ($lines && is_array($lines)) {
        $items = [];
        foreach ($lines as $line) {
            $j = @json_decode($line, true);
            if ($j && isset($j['ts'], $j['type'], $j['summary'], $j['tab'])) {
                $items[] = $j;
            }
        }
        $recent = array_slice($items, -5);
    }
}
if (!$recent) {
    echo '<li style="color:#888;">No recent activity.</li>';
} else {
    foreach ($recent as $item) {
        $date = htmlspecialchars(date("Y-m-d H:i", strtotime($item['ts'])));
        $type = htmlspecialchars(ucfirst($item['type']));
        $summary = htmlspecialchars($item['summary']);
        $tab = htmlspecialchars($item['tab']);
        $tabLabel = ($tab === 'assistant' ? 'Assistant' : ($tab === 'analyze' ? 'Analyze' : ucfirst($tab)));
        $link = "/ai_assistant.php?tab=" . urlencode($tab);
        echo "<li><span class='ai-recent-date'>$date</span><span class='ai-recent-type'>$type</span>";
        echo "<span class='ai-recent-summary'>$summary</span> ";
        echo "<a href='$link' class='btn btn-xxs btn-link' style='font-size:.95em;padding-left:.7em;'>View</a></li>";
    }
}
?>
    </ul>
  </div>
</div>