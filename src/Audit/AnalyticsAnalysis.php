<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Annotation\Param;
use Drutiny\Annotation\Token;

/**
 * @Param(
 *  name = "expression",
 *  type = "string",
 *  description = "An expression to evaluate to determine the outcome of the audit",
 * )
 * @Token(
 *  name = "invalid_actions",
 *  type = "array",
 *  description = "A keyed list of actions the page rule that don't match the values set in the settings parameter.",
 * )
 */
class AnalyticsAnalysis extends AbstractAnalysis {
  use ApiEnabledAuditTrait;

  /**
   * {@inheritdoc}
   */
  public function gather(Sandbox $sandbox)
  {
    $uri = $sandbox->getTarget()->uri();
    $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
    $sandbox->setParameter('host', $host);

    $zone  = $this->zoneInfo($sandbox->getParameter('zone', $host));
    $sandbox->setParameter('zone', $zone['name']);

    $query = http_build_query([
      'since' => $sandbox->getReportingPeriodStart()->format(\DateTime::RFC3339),
      'until' => $sandbox->getReportingPeriodEnd()->format(\DateTime::RFC3339),
    ]);

    $response = $this->api()->request("GET", "zones/{$zone['id']}/analytics/dashboard?$query");

    foreach ($response as $key => $value) {
      $sandbox->setParameter($key, $value);
    }
  }
}

 ?>
