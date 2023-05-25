<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Cloudflare\Client;
use Symfony\Component\Yaml\Yaml;

/**
 * 
 */
class ZoneAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    /**
     * {@inheritdoc}
     */
    public function gather(Client $client)
    {
        $this->set('host', $this->target['domain']);

        $this->set('zone', $this->target['cloudflare.zone']->export());

        $response = $client->request("GET", "zones/{$this->target['cloudflare.zone.id']}/settings");

        // Provide keyed versions too.
        foreach ($response['result'] as &$setting) {
            $setting['name'] = implode(' ', array_map('ucwords', explode('_', $setting['id'])));

            $setting['name'] = strtr(
                $setting['name'], [
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

            $setting['data'] = $setting['value'];
            $setting['value'] = Yaml::dump($setting['value'], 0);
            $this->set($setting['id'], $setting);
        }

        $this->set('settings', $response['result']);
    }
}

?>
