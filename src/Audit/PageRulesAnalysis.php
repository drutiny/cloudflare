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
 *  name = "expression",
 *  type = "string",
 *  description = "An ExpressionLanguage expression to evaluate the outcome of a page rule.",
 * )
 * @Param(
 *  name = "not_applicable",
 *  type = "string",
 *  default = "false",
 *  description = "The expression language to evaludate if the analysis is not applicable. See https://symfony.com/doc/current/components/expression_language/syntax.html"
 * )
 * @Token(
 *  name = "settings",
 *  type = "array",
 *  description = "A keyed list of settings for a rule.",
 * )
 */
class PageRulesAnalysis extends AbstractAnalysis {
  use ApiEnabledAuditTrait;
  public function gather(Sandbox $sandbox)
  {
    $uri = $sandbox->getTarget()->uri();
    $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
    $sandbox->setParameter('host', $host);

    $zone  = $this->zoneInfo($sandbox->getParameter('zone', $host));
    $sandbox->setParameter('zone', $zone['name']);

    $response = $this->api()->request('GET', "zones/{$zone['id']}/pagerules");

    foreach ($response['result'] as &$pagerule) {
      $pagerule['target'] = str_replace('*', '\*', $pagerule['targets'][0]['constraint']['value']);
      //$pagerule['formatted_actions'] = Yaml::dump($pagerule['actions']);
      foreach ($pagerule['actions'] as $idx => &$action) {
        $action['formatted_title'] = strtr(ucwords(str_replace('_', ' ', $action['id'])), [
          'Tls' => 'TLS',
          'Ttl' => 'TTL',
          'Ddos' => 'DDOS',
          'Https' => 'HTTPS',
          'Ip' => 'IP',
          'Waf' => 'WAF',
          'Ssl' => 'SSL',
          'Http' => 'HTTP',
          'Cname' => 'CNAME'
        ]);

        if (!isset($action['value'])) {
          $pagerule['flags'][] = $action;
          unset($pagerule['actions'][$idx]);
          continue;
        }

        $action['formatted_value'] = Yaml::dump($action['value'], 0);
      }

      $pagerule['actions'] = array_values($pagerule['actions']);
    }

    $sandbox->setParameter('pagerules', $response['result']);
  }
}

 ?>
