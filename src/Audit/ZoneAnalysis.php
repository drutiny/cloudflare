<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Sandbox\Sandbox;
use Symfony\Component\Yaml\Yaml;

/**
 * @Token(
 *  name = "invalid_actions",
 *  type = "array",
 *  description = "A keyed list of actions the page rule that don't match the values set in the settings parameter.",
 * )
 */
class ZoneAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function configure()
    {
        $this->addParameter(
            'expression',
            static::PARAMETER_OPTIONAL,
            'An expression to evaluate to determine the outcome of the audit',
            ''
        );

    }

    /**
     * {@inheritdoc}
     */
    public function gather(Sandbox $sandbox)
    {
        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host));
        $this->set('zone', $zone['name']);

        $response = $this->api()->request("GET", "zones/{$zone['id']}/settings");


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
