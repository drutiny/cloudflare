<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\UseService;
use Drutiny\Sandbox\Sandbox;
use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Cloudflare\Client;

/**
 * 
 */
#[UseService(id: Client::class, method: 'setClient')]
class PageRuleAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function configure():void
    {
        $this->addParameter(
            'query',
            static::PARAMETER_REQUIRED,
            'The GraphQL query to send to the Cloudflare GraphQL API endpoint.',
            NULL
        );
        parent::configure();
    }

    public function gather(Sandbox $sandbox)
    {
        $response = $this->api()->request('POST', 'graphql', [
            'body' => $this->interpolate($this->getParameter('graphql'))
        ]);
        $this->set('data', $response['data']);
        $this->set('errors', $response['errors']);
    }
}

?>
