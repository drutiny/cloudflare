<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\Parameter;
use Drutiny\Cloudflare\Client;
use Drutiny\Audit\AbstractAnalysis;

/**
 * 
 */
#[Parameter(
    name: 'zone',
    description: 'The apex domain registered with Cloudflare.',
)]
class AccountMembersAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function gather(Client $client)
    {
        $this->setClient($client);

        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host));
        $this->set('zone', $zone['name']);

        $accounts = [];
        $page = 1;

        do {
            $response = $client->request(
                'GET', "accounts/{$zone['account']['id']}/members", ['query' => [
                'per_page' => 50,
                'page' => $page
                ]]
            );
            $page++;
            $accounts += $response['result'];
        }
        while (!empty($response['result']));

        if ($pattern = $this->getParameter('exclude')) {
            $accounts = array_filter(
                $accounts, function ($account) use ($pattern) {
                    return strpos($account['user']['email'], $pattern) === false;
                }
            );
        }

        $this->set('accounts', array_values($accounts));
    }
}

?>
