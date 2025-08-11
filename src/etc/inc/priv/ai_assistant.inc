<?php
/* Custom privilege for AI Assistant page */
if (!is_array($priv_list)) { $priv_list = array(); }
$priv_list['page-diagnostics-ai-assistant'] = array();
$priv_list['page-diagnostics-ai-assistant']['name'] = gettext('WebCfg - Diagnostics: AI Assistant');
$priv_list['page-diagnostics-ai-assistant']['descr'] = gettext("Allow access to the 'Diagnostics: AI Assistant' page.");
$priv_list['page-diagnostics-ai-assistant']['match'] = array();
$priv_list['page-diagnostics-ai-assistant']['match'][] = 'ai_assistant.php*';
?>