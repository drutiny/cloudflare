<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;
use Symfony\Component\Yaml\Yaml;
use Drutiny\Audit\AbstractAnalysis;

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
 *  name = "expression",
 *  type = "string",
 *  description = "An ExpressionLanguage expression to evaluate the outcome of a page rule.",
 * )
 * @Token(
 *  name = "settings",
 *  type = "array",
 *  description = "A keyed list of settings for a rule.",
 * )
 */
class PageRuleAnalysis extends AbstractAnalysis {
  use ApiEnabledAuditTrait;
  public function gather(Sandbox $sandbox)
  {
    $uri = $sandbox->getTarget()->uri();
    $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
    $sandbox->setParameter('host', $host);

    $zone  = $this->zoneInfo($sandbox->getParameter('zone', $host));
    $sandbox->setParameter('zone', $zone['name']);

    $response = $this->api()->request('GET', "zones/{$zone['id']}/pagerules");

    // Create a reusable translation function to allow settings to use variables.
    $t = function ($v) use ($zone, $host) {
      return strtr($v, [
        ':zone' => $zone['name'],
        ':host' => $host
      ]);
    };

    $constraint = $t($sandbox->getParameter('rule'));
    $sandbox->setParameter('rule', $constraint);

    $rules = array_filter($response['result'], function ($rule) use ($constraint) {
      return $rule['targets'][0]['constraint']['value'] == $constraint;
    });

    if (!count($rules)) {
      throw new \Exception("Cannot find a rule for $constraint.");
    }

    // Build action array.
    $rule = array_shift($rules);
    $sandbox->setParameter('settings', $rule);

    foreach ($rule['actions'] as $value) {
      $rule[$value['id']] = isset($value['value']) ? $value['value'] : TRUE;
    }

    $sandbox->setParameter('settings', $rule);
  }
}

 ?>
