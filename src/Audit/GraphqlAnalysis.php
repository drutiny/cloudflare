<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\Parameter;
use Drutiny\Attribute\Type;
use Drutiny\Audit\AbstractAnalysis;
use Drutiny\Cloudflare\Client;

/**
 * 
 */
#[Parameter(
    name: 'query',
    mode: Parameter::REQUIRED,
    type: Type::STRING,
    description: 'The GraphQL query to send to the Cloudflare GraphQL API endpoint.'
)]
class PageRuleAnalysis extends AbstractAnalysis
{
    use ApiEnabledAuditTrait;

    public function gather(Client $client)
    {
        $response = $client->request('POST', 'graphql', [
            'body' => $this->interpolate($this->getParameter('graphql'))
        ]);
        $this->set('data', $response['data']);
        $this->set('errors', $response['errors']);
    }
}

?>
