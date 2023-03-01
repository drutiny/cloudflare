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
class AccountMembersAnalysis extends AbstractAnalysis
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

        $accounts = [];
        $page = 1;

        do {
            $response = $this->api()->request(
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
