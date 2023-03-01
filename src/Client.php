<?php

namespace Drutiny\Cloudflare;

use Drutiny\Http\Client as HttpClient;
use GuzzleHttp\ClientInterface;
use Drutiny\Attribute\Plugin;
use Drutiny\Attribute\PluginField;
use Drutiny\Plugin as DrutinyPlugin;
use Drutiny\Plugin\FieldType;

#[Plugin(name: 'cloudflare:api')]
#[PluginField(
  name: 'email',
  description: "The email address you use to login to Cloudflare with:",
  type: FieldType::CREDENTIAL
)]
#[PluginField(
  name: 'key',
  description: 'The Cloudflare API key. This can be obtained from the Cloudflare UI:',
  type: FieldType::CREDENTIAL
)]
class Client {

  /**
   * API base URL for Cloudflare.
   */
  const API_BASE = 'https://api.cloudflare.com/client/v4/';
  
  /**
   * API constructor.
   */
  public function __construct(protected DrutinyPlugin $plugin, protected HTTPClient $http) {
   
  }

  /**
   * Informs if the Cloudflare API has been configured in Drutiny.
   */
  public function isInstalled():bool
  {
    return $this->plugin->isInstalled();
  }

  /**
   * Get an HTTP client for interacting with the CLoudflare API.
   * 
   * @throws PluginRequiredException.
   */
  public function getClient():ClientInterface
  {
    return $this->http->create([
      'base_uri' => self::API_BASE,
      'headers' => [
        'X-Auth-Email' => $this->plugin->email,
        'X-Auth-Key' => $this->plugin->key,
        'User-Agent' => 'drutiny-cloudflare/4.x',
        'Accept' => 'application/json',
        'Accept-Encoding' => 'gzip'
      ],
      'decode_content' => 'gzip',
      'allow_redirects' => FALSE,
      'connect_timeout' => 10,
      'timeout' => 300,
    ]);
  }

  /**
   * Perform an API request to Cloudflare.
   *
   * @param string $method
   *   The HTTP method to use.
   * @param string $endpoint
   *   The API endpoint to hit. The endpoint is prefixed with the API_BASE.
   * @param array $payload
   *
   * @param bool $decodeBody
   *   Whether the body should be JSON decoded.
   * @return array|string
   *   Decoded JSON body of the API request, if the request was successful.
   *
   * @throws \Exception
   */
  public function request($method, $endpoint, array $options = [], $decodeBody = TRUE) {

    $response = $this->getClient()->request($method, $endpoint, $options);

    if (!in_array($response->getStatusCode(), [200, 204])) {
      throw new \Exception('Error: ' . (string) $response->getBody());
    }

    if ($decodeBody) {
      return json_decode($response->getBody(), TRUE);
    }
    return (string) $response->getBody();
  }

}
