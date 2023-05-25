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
#[Parameter(
    name: 'rule',
    description: 'The page rule pattern to look up.',
)]
class PageRuleAnalysis extends AbstractAnalysis
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

        // Create a reusable translation function to allow settings to use variables.
        $t = function ($v) use ($zone, $host) {
            return strtr(
                $v, [
                ':zone' => $zone['name'],
                ':host' => $host
                ]
            );
        };

        $constraint = $t($this->getParameter('rule'));


        $rules = array_filter(
            $response['result'], function ($rule) use ($constraint) {
                return $rule['targets'][0]['constraint']['value'] == $constraint;
            }
        );

        // If we couldn't find an explicit match, see if there is a match on another
        // page rule.
        if (!count($rules)) {

            $rules = array_filter(
                $response['result'], function ($rule) use ($constraint) {
                    return fnmatch($rule['targets'][0]['constraint']['value'], $constraint);
                }
            );

            if (!count($rules)) {
                  throw new \Exception("Cannot find a rule for $constraint.");
            }
        }

        // Build action array.
        $rule = array_shift($rules);
        $this->set('settings', $rule);
        $this->set('rule', $rule['targets'][0]['constraint']['value']);

        foreach ($rule['actions'] as $value) {
            $rule[$value['id']] = isset($value['value']) ? $value['value'] : true;
        }

        $this->set('settings', $rule);
    }
}

?>
