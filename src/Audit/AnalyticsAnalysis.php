<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\Parameter;
use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Cloudflare\Client;

/**
 * 
 */
#[Parameter(
    name: 'zone',
    description: 'The apex domain registered with Cloudflare.',
)]
class AnalyticsAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    /**
     * {@inheritdoc}
     */
    public function gather(Client $client)
    {
        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host), $client);
        $this->set('zone', $zone['name']);

        $response = $client->request(
            "GET", "zones/{$zone['id']}/analytics/dashboard", ['query' => [
            'since' => $this->reportingPeriodStart->format(\DateTime::RFC3339),
            'until' => $this->reportingPeriodEnd->format(\DateTime::RFC3339),
            ]]
        );

        foreach ($response as $key => $value) {
            $this->set($key, $value);
        }
    }
}

?>
