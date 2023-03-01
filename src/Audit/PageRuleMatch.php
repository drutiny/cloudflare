<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Attribute\UseService;
use Drutiny\Cloudflare\Client;
use Drutiny\Sandbox\Sandbox;
use Symfony\Component\Yaml\Yaml;

/**
 *
 */
#[UseService(id: Client::class, method: 'setClient')]
class PageRuleMatch extends ApiEnabledAudit {

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
        'settings',
        static::PARAMETER_OPTIONAL,
        'A keyed list of actions the page rule should action.',
        ''
      );
  }

  public function audit(Sandbox $sandbox)
  {
    $uri = $this->target['uri'];
    $host = strpos($uri, 'http') === 0 ? parse_url($uri, PHP_URL_HOST) : $uri;
    $this->set('host', $host);

    $zone  = $this->zoneInfo($this->getParameter('zone', $host));
    $this->set('zone', $zone['name']);

    $response = $this->api()->request('GET', "zones/{$zone['id']}/pagerules");

    // Create a reusable translation function to allow settings to use variables.
    $t = function ($v) use ($zone, $host) {
      return strtr($v, [
        ':zone' => $zone['name'],
        ':host' => $host
      ]);
    };

    $constraint = $t($this->getParameter('rule'));
    $this->set('rule', $constraint);


    $rules = array_filter($response['result'], function ($rule) use ($constraint) {
      return $rule['targets'][0]['constraint']['value'] == $constraint;
    });

    if (!count($rules)) {
      return FALSE;
    }

    // Build action array.
    $rule = array_shift($rules);
    foreach ($rule['actions'] as $action) {
      $actions[$action['id']] = isset($action['value']) ? $action['value'] : TRUE;
    }
    $this->recurKsort($actions);
    $this->set('actions', $actions);

    // Build settings array.
    $settings = $this->getParameter('settings');
    if (isset($settings['forwarding_url'])) {
      $settings['forwarding_url']['url'] = $t($settings['forwarding_url']['url']);
    }
    $this->recurKsort($settings);
    $this->set('settings', $settings);

    // Format parameters so that array_diff_(key|assoc) can do the correct job.
    $settings = array_map(['Symfony\Component\Yaml\Yaml', 'dump'], $settings);
    $actions = array_map(['Symfony\Component\Yaml\Yaml', 'dump'], $actions);

    // Calculate the differences.
    $extra_actions = array_diff_key($actions, $settings);
    $test_actions = array_diff_key($actions, $extra_actions);
    $invalid_actions = array_diff_assoc($test_actions, $settings);

    // Format parameters so that array_diff_(key|assoc) can do the correct job.
    $extra_actions = array_map(['Symfony\Component\Yaml\Yaml', 'parse'], $extra_actions);
    $invalid_actions = array_map(['Symfony\Component\Yaml\Yaml', 'parse'], $invalid_actions);

    $this->set('extra_actions', $extra_actions);
    $this->set('invalid_actions', $invalid_actions);
    $this->set('invalid_actions_array', array_map(function ($key, $value) {
      return ['id' => $key, 'value' => Yaml::dump($value)];
    }, array_keys($invalid_actions), array_values($invalid_actions)));

    $this->set('settings_array', array_map(function ($key, $value) {
      return ['id' => $key, 'value' => $value];
    }, array_keys($settings), array_values($settings)));

    $sandbox->logger()->info(__CLASS__ . PHP_EOL . Yaml::dump(['parameters' => $this->getParameterTokens()], 6));

    return empty($invalid_actions);
  }

  protected function recurKsort(&$array)
  {
     foreach ($array as &$value) {
        if (is_array($value)) $this->recurKsort($value);
     }
     return ksort($array);
  }
}

 ?>
