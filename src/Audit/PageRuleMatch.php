<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;

/**
 * @Param(
 *  name = "zone",
 *  type = "string",
 *  description = "The apex domain registered with Cloudflare.",
 * )
 * @Param(
 *  name = "rule",
 *  type = "string",
 *  description = "The page rule pattern to look up.",
 * )
 * @Param(
 *  name = "settings",
 *  type = "array",
 *  description = "A keyed list of actions the page rule should action.",
 * )
 * @Token(
 *  name = "actions",
 *  type = "array",
 *  description = "A keyed list of actions the page rule contains.",
 * )
 * @Token(
 *  name = "extra_actions",
 *  type = "array",
 *  description = "A keyed list of actions the page rule contains that are not listed in the settings parameter.",
 * )
 * @Token(
 *  name = "invalid_actions",
 *  type = "array",
 *  description = "A keyed list of actions the page rule that don't match the values set in the settings parameter.",
 * )
 */
class PageRuleMatch extends ApiEnabledAudit {
  public function audit(Sandbox $sandbox)
  {
    $uri = $sandbox->drush()->getGlobalDefaultOption('uri');
    $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;

    $zone  = $this->zoneInfo($sandbox->getParameter('zone', $host));
    $response = $this->api()->request('GET', "zones/{$zone['id']}/pagerules");

    $constraint = strtr($sandbox->getParameter('rule'), [
      ':zone' => $zone['name'],
    ]);

    $rules = array_filter($response['result'], function ($rule) use ($constraint) {
      return $rule['targets'][0]['constraint']['value'] == $constraint;
    });

    if (!count($rules)) {
      return FALSE;
    }

    $rule = array_shift($rules);
    foreach ($rule['actions'] as $action) {
      $actions[$action['id']] = isset($action['value']) ? $action['value'] : TRUE;
    }

    $settings = $sandbox->getParameter('settings');

    $extra_actions = array_diff_key($actions, $settings);
    $test_actions = array_diff_key($actions, $extra_actions);
    $invalid_actions = array_diff_assoc($settings, $test_actions);

    $sandbox->setParameter('actions', $actions);
    $sandbox->setParameter('extra_actions', $extra_actions);
    $sandbox->setParameter('invalid_actions', $invalid_actions);

    return empty($invalid_actions);
  }
}

 ?>
