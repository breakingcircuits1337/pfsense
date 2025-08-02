&lt;?php
/*
 * services_ai_settings.php
 * pfSense AI Assistant settings/config page
 */

require_once("guiconfig.inc");
require_once("/etc/inc/ai.inc");

$ai_path = array('system', 'ai');
$pconfig = array(
    'provider' =&gt; $config['system']['ai']['default_provider'] ?? 'gemini',
    'apikey_gemini' =&gt; $config['system']['ai']['gemini']['apikey'] ?? '',
    'apikey_mistral' =&gt; $config['system']['ai']['mistral']['apikey'] ?? '',
    'apikey_groq' =&gt; $config['system']['ai']['groq']['apikey'] ?? '',
    'voice_enable' =&gt; $config['system']['ai']['voice_enable'] ?? false,
);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $provider = $_POST['provider'] ?? 'gemini';
    $config['system']['ai']['default_provider'] = $provider;
    $config['system']['ai']['gemini']['apikey']  = $_POST['apikey_gemini'] ?? '';
    $config['system']['ai']['mistral']['apikey'] = $_POST['apikey_mistral'] ?? '';
    $config['system']['ai']['groq']['apikey']    = $_POST['apikey_groq'] ?? '';
    $config['system']['ai']['voice_enable'] = isset($_POST['voice_enable']);

    write_config("AI Assistant settings updated");
    $savemsg = "Settings saved successfully.";
    $pconfig = array(
        'provider' =&gt; $provider,
        'apikey_gemini' =&gt; $config['system']['ai']['gemini']['apikey'],
        'apikey_mistral' =&gt; $config['system']['ai']['mistral']['apikey'],
        'apikey_groq' =&gt; $config['system']['ai']['groq']['apikey'],
        'voice_enable' =&gt; $config['system']['ai']['voice_enable'],
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
    &lt;div class="form-group"&gt;
      &lt;label&gt;Gemini API Key&lt;/label&gt;
      &lt;input type="text" class="form-control" name="apikey_gemini" value="<?=htmlspecialchars($pconfig['apikey_gemini'])?>" autocomplete="off"&gt;
    &lt;/div&gt;
    &lt;div class="form-group"&gt;
      &lt;label&gt;Mistral API Key&lt;/label&gt;
      &lt;input type="text" class="form-control" name="apikey_mistral" value="<?=htmlspecialchars($pconfig['apikey_mistral'])?>" autocomplete="off"&gt;
    &lt;/div&gt;
    &lt;div class="form-group"&gt;
      &lt;label&gt;Groq API Key&lt;/label&gt;
      &lt;input type="text" class="form-control" name="apikey_groq" value="<?=htmlspecialchars($pconfig['apikey_groq'])?>" autocomplete="off"&gt;
    &lt;/div&gt;
    &lt;div class="checkbox"&gt;
      &lt;label&gt;
        &lt;input type="checkbox" name="voice_enable" <?=!empty($pconfig['voice_enable'])?'checked':''?&gt;&gt; Enable voice features (speech recognition &amp; TTS)
      &lt;/label&gt;
    &lt;/div&gt;
    &lt;button class="btn btn-primary" type="submit"&gt;Save&lt;/button&gt;
  &lt;/div&gt;
&lt;/div&gt;
&lt;/form&gt;

<?php include("foot.inc"); ?>