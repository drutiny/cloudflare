<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;
use Symfony\Component\Yaml\Yaml;
use Drutiny\Audit\AbstractAnalysis;

/**
 * @Token(
 *  name = "settings",
 *  type = "array",
 *  description = "A keyed list of settings for a rule.",
 * )
 */
class PageRuleAnalysis extends AbstractAnalysis
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
            'rule',
            static::PARAMETER_OPTIONAL,
            'The page rule pattern to look up.',
            ''
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

        $response = $this->api()->request('GET', "zones/{$zone['id']}/pagerules");

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
