&lt;?php
/*
 * services_ai_settings.php
 * pfSense AI Assistant settings/config page
 */

require_once("guiconfig.inc");
require_once("/etc/inc/ai.inc");

$ai_path = array('system', 'ai');
$pconfig = array(
    'provider' => $config['system']['ai']['default_provider'] ?? 'gemini',
    'apikey_gemini' => $config['system']['ai']['gemini']['apikey'] ?? '',
    'apikey_mistral' => $config['system']['ai']['mistral']['apikey'] ?? '',
    'apikey_groq' => $config['system']['ai']['groq']['apikey'] ?? '',
    'apikey_shodan' => $config['system']['ai']['shodan']['apikey'] ?? '',
    'voice_enable' => $config['system']['ai']['voice_enable'] ?? false,
    'monitor_enable' => $config['system']['ai']['monitor']['enable'] ?? false,
    'gemini_model' => $config['system']['ai']['gemini']['model'] ?? 'gemini-pro',
    'mistral_model' => $config['system']['ai']['mistral']['model'] ?? 'mistral-tiny',
    'groq_model' => $config['system']['ai']['groq']['model'] ?? 'mixtral-8x7b-32768',
);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $provider = $_POST['provider'] ?? 'gemini';
    $config['system']['ai']['default_provider'] = $provider;
    $config['system']['ai']['gemini']['apikey']  = $_POST['apikey_gemini'] ?? '';
    $config['system']['ai']['mistral']['apikey'] = $_POST['apikey_mistral'] ?? '';
    $config['system']['ai']['groq']['apikey']    = $_POST['apikey_groq'] ?? '';
    $config['system']['ai']['shodan']['apikey']  = $_POST['apikey_shodan'] ?? '';
    $config['system']['ai']['voice_enable'] = isset($_POST['voice_enable']);
    $config['system']['ai']['monitor']['enable'] = isset($_POST['monitor_enable']);
    $config['system']['ai']['gemini']['model'] = $_POST['gemini_model'] ?? 'gemini-pro';
    $config['system']['ai']['mistral']['model'] = $_POST['mistral_model'] ?? 'mistral-tiny';
    $config['system']['ai']['groq']['model'] = $_POST['groq_model'] ?? 'mixtral-8x7b-32768';
    $config['system']['ai']['monitor']['threshold'] =
        isset($_POST['monitor_threshold']) && is_numeric($_POST['monitor_threshold']) ? floatval($_POST['monitor_threshold']) : 0.7;
    $config['system']['ai']['monitor']['block_ttl_hours'] =
        isset($_POST['monitor_block_ttl_hours']) && is_numeric($_POST['monitor_block_ttl_hours']) ? intval($_POST['monitor_block_ttl_hours']) : 24;

    write_config("AI Assistant settings updated");
    $savemsg = "Settings saved successfully.";
    $pconfig = array(
        'provider' => $provider,
        'apikey_gemini' => $config['system']['ai']['gemini']['apikey'],
        'apikey_mistral' => $config['system']['ai']['mistral']['apikey'],
        'apikey_groq' => $config['system']['ai']['groq']['apikey'],
        'apikey_shodan' => $config['system']['ai']['shodan']['apikey'],
        'voice_enable' => $config['system']['ai']['voice_enable'],
        'monitor_enable' => $config['system']['ai']['monitor']['enable'],
        'gemini_model' => $config['system']['ai']['gemini']['model'],
        'mistral_model' => $config['system']['ai']['mistral']['model'],
        'groq_model' => $config['system']['ai']['groq']['model'],
    );
}

include("head.inc");
?>

&lt;form method="post"&gt;
&lt;div class="panel panel-default"&gt;
  &lt;div class="panel-heading"&gt;&lt;h2 class="panel-title"&gt;AI Assistant Settings&lt;/h2&gt;&lt;/div&gt;
  &lt;div class="panel-body"&gt;
    <?php if (isset($savemsg)): ?>
      &lt;div class="alert alert-success"&gt;<?=$savemsg?>&lt;/div&gt;
    <?php endif; ?>
    &lt;div class="form-group"&gt;
      &lt;label&gt;Default AI Provider&lt;/label&gt;
      &lt;select class="form-control" name="provider"&gt;
        &lt;option value="gemini" <?=($pconfig['provider']=='gemini')?'selected':''?&gt;&gt;Gemini&lt;/option&gt;
        &lt;option value="mistral" <?=($pconfig['provider']=='mistral')?'selected':''?&gt;&gt;Mistral&lt;/option&gt;
        &lt;option value="groq" <?=($pconfig['provider']=='groq')?'selected':''?&gt;&gt;Groq&lt;/option&gt;
      &lt;/select&gt;
    &lt;/div&gt;
    <div class="form-group">
      <label>Gemini API Key</label>
      <input type="text" class="form-control" name="apikey_gemini" value="<?=htmlspecialchars($pconfig['apikey_gemini'])?>" autocomplete="off">
      <label class="mt-2">Gemini Model</label>
      <input type="text" class="form-control" name="gemini_model" value="<?=htmlspecialchars($pconfig['gemini_model'])?>" autocomplete="off">
    </div>
    <div class="form-group">
      <label>Mistral API Key</label>
      <input type="text" class="form-control" name="apikey_mistral" value="<?=htmlspecialchars($pconfig['apikey_mistral'])?>" autocomplete="off">
      <label class="mt-2">Mistral Model</label>
      <input type="text" class="form-control" name="mistral_model" value="<?=htmlspecialchars($pconfig['mistral_model'])?>" autocomplete="off">
    </div>
    <div class="form-group">
      <label>Groq API Key</label>
      <input type="text" class="form-control" name="apikey_groq" value="<?=htmlspecialchars($pconfig['apikey_groq'])?>" autocomplete="off">
      <label class="mt-2">Groq Model</label>
      <input type="text" class="form-control" name="groq_model" value="<?=htmlspecialchars($pconfig['groq_model'])?>" autocomplete="off">
    </div>
    <div class="form-group">
      <label>Shodan API Key (Optional)</label>
      <input type="text" class="form-control" name="apikey_shodan" value="<?=htmlspecialchars($pconfig['apikey_shodan'])?>" autocomplete="off">
      <span class="help-block">If provided, the AI Monitor will query Shodan for context on attackers.</span>
    </div>
    <div class="checkbox">
      <label>
        <input type="checkbox" name="voice_enable" <?=!empty($pconfig['voice_enable'])?'checked':''?>> Enable voice features (speech recognition & TTS)
      </label>
    </div>
    <div class="form-group">
      <label>Confidence Threshold</label>
      <input type="number" min="0" max="1" step="0.05" class="form-control" name="monitor_threshold" value="<?=htmlspecialchars($config['system']['ai']['monitor']['threshold'] ?? '0.7')?>">
      <span class="help-block">Only block if confidence is at or above this value (0–1).</span>
    </div>
    <div class="form-group">
      <label>Block Lifespan (hours)</label>
      <input type="number" min="1" step="1" class="form-control" name="monitor_block_ttl_hours" value="<?=htmlspecialchars($config['system']['ai']['monitor']['block_ttl_hours'] ?? '24')?>">
      <span class="help-block">How many hours each IP remains blocked before automatic unblock.</span>
    </div>
    <div class="checkbox">
      <label>
        <input type="checkbox" name="monitor_enable" <?=!empty($pconfig['monitor_enable'])?'checked':''?>> Enable Threat Monitor
      </label>
    </div>
    <button class="btn btn-primary" type="submit">Save</button>
  </div>
</div>
</form>

<?php include("foot.inc"); ?>