<?php

namespace Drutiny\Cloudflare\Audit;

use Drutiny\Cloudflare\Client;
use Drutiny\Audit;
use Drutiny\Sandbox\Sandbox;

abstract class ApiEnabledAudit extends Audit {
  static public function credentialFilepath()
  {
    return sprintf('%s/.drutiny/cloudflare.json', $_SERVER['HOME']);
  }

  protected function getEmail()
  {
    $data = file_get_contents(self::credentialFilepath());
    $data = json_decode($data, TRUE);
    return $data['email'];
  }

  protected function getKey()
  {
    $data = file_get_contents(self::credentialFilepath());
    $data = json_decode($data, TRUE);
    return $data['key'];
  }

  public function requireApiCredentials()
  {
    $creds = self::credentialFilepath();
    if (!file_exists($creds)) {
      throw new InvalidArgumentException("Cloudflare credentials need to be setup. Please run setup:cloudflare.");
    }
    return TRUE;
  }

  protected function api()
  {
    return new Client($this->getEmail(), $this->getKey());
  }

  protected function zoneInfo($zone)
  {
    $original_zone = $zone;
    $names = explode('.', $zone);

    while ($zone = implode('.', $names)) {
      $results = $this->api()->request('GET', 'zones?page=1&name=' . $zone . '&per_page=20');
      $number_of_matches = count($results['result']);

      // If zone passed is actually a subdomain, then pop a name of the domain
      // and reattempt to find the zone.
      if ($number_of_matches !== 1) {
        array_shift($names);
        continue;
      }
      return $results['result'][0];
    }
    throw new \Exception("There is no zone with that name: {$original_zone}.");
  }
}

 ?>
