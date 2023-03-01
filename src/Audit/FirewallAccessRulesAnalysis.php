<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\UseService;
use Drutiny\Cloudflare\Client;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Audit\AbstractAnalysis;

/**
 * 
 */
#[UseService(id: Client::class, method: 'setClient')]
class FirewallAccessRulesAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function configure():void
    {
        $this->addParameter(
            'zone',
            static::PARAMETER_OPTIONAL,
            'The apex domain registered with Cloudflare.',
            NULL
        );
        $this->addParameter(
            'expression',
            static::PARAMETER_OPTIONAL,
            'A Twig expression to evaluate the outcome of a page rule.',
            ''
        );
        $this->addParameter(
            'not_applicable',
            static::PARAMETER_OPTIONAL,
            'The expression language to evaludate if the analysis is not applicable. See https://symfony.com/doc/current/components/expression_language/syntax.html',
            'false'
        );

    }

    public function gather(Sandbox $sandbox)
    {
        $uri = $this->target['uri'];
        $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
        $this->set('host', $host);

        $zone  = $this->zoneInfo($this->getParameter('zone', $host));
        $this->set('zone', $zone['name']);

        $response = $this->api()->request('GET', "zones/{$zone['id']}/firewall/access_rules/rules");

        $this->set('rules', $response['result']);
    }
}

?>
