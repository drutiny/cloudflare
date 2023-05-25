<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\Parameter;
use Drutiny\Attribute\UseService;
use Drutiny\Cloudflare\Client;
use Drutiny\Audit\AbstractAnalysis;

/**
 * 
 */
#[UseService(id: Client::class, method: 'setClient')]
#[Parameter(
    name: 'zone',
    description: 'The apex domain registered with Cloudflare.',
)]
class FirewallAccessRulesAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function gather(Client $client)
    {
        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host), $client);
        $this->set('zone', $zone['name']);

        $response = $client->request('GET', "zones/{$zone['id']}/firewall/access_rules/rules");

        $this->set('rules', $response['result']);
    }
}

?>
