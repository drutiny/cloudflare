<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\Parameter;
use Drutiny\Cloudflare\Client;
use Symfony\Component\Yaml\Yaml;
use Drutiny\Audit\AbstractAnalysis;

/**
 * 
 */
#[Parameter(
    name: 'zone',
    description: 'The apex domain registered with Cloudflare.',
  )]
class PageRulesAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function gather(Client $client)
    {
        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host), $client);
        $this->set('zone', $zone['name']);

        $response = $client->request('GET', "zones/{$zone['id']}/pagerules");

        foreach ($response['result'] as &$pagerule) {
            $pagerule['target'] = str_replace('*', '\*', $pagerule['targets'][0]['constraint']['value']);
            //$pagerule['formatted_actions'] = Yaml::dump($pagerule['actions']);
            foreach ($pagerule['actions'] as $idx => &$action) {
                $action['formatted_title'] = strtr(
                    ucwords(str_replace('_', ' ', $action['id'])), [
                    'Tls' => 'TLS',
                    'Ttl' => 'TTL',
                    'Ddos' => 'DDOS',
                    'Https' => 'HTTPS',
                    'Ip' => 'IP',
                    'Waf' => 'WAF',
                    'Ssl' => 'SSL',
                    'Http' => 'HTTP',
                    'Cname' => 'CNAME'
                    ]
                );

                if (!isset($action['value'])) {
                      $pagerule['flags'][] = $action;
                      unset($pagerule['actions'][$idx]);
                      continue;
                }

                $action['formatted_value'] = Yaml::dump($action['value'], 0);
            }

            $pagerule['actions'] = array_values($pagerule['actions']);
        }

        $this->set('pagerules', $response['result']);
    }
}

?>
