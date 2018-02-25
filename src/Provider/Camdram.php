<?php
namespace Acts\Camdram\Oauth2\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use Acts\Camdram\OAuth2\Provider\CamdramUser;
use Acts\Camdram\OAuth2\Provider\Exception\CamdramIdentityProviderException;

class Camdram extends AbstractProvider
{
    use BearerAuthorizationTrait;
    /**
     * Camdram domain
     *
     * @var string
     */
    public $domain = 'https://www.camdram.net';
    
    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->domain.'/oauth/v2/auth';
    }
    
    /**
     * Get access token url to retrieve token
     *
     * @param  array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->domain.'/oauth/v2/token';
    }
    
    /**
     * Get provider url to fetch user details
     *
     * @param  AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->domain.'/auth/account.json';
    }
    
    public function getAuthenticatedData($uri, AccessToken $token)
    {
        $options = ['headers' => 'Accept: application/json'];
        $request = $this->getAuthenticatedRequest('GET', $this->domain.$uri, $token, $options);
        $response = $this->getResponse($request);
        $data = $this->parseResponse($response);
        $this->checkResponse($response, $data);
        return $data;
    }
    
    public function getAuthorisedShows(AccessToken $token)
    {
        return $this->getAuthenticatedData('/auth/account/shows.json', $token);
    }
    
    public function getAuthorisedOrganisations(AccessToken $token)
    {
        return $this->getAuthenticatedData('/auth/account/organisations.json', $token);
    }
    
    /**
     * Get the default scopes used by this provider.
     *
     * This should not be a complete list of all scopes, but the minimum
     * required for the provider user interface!
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [];
    }
    
    /**
     * Check a provider response for errors.
     *
     * @throws CamdramIdentityProviderException
     * @param  ResponseInterface $response
     * @param  array $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400) {
            throw CamdramIdentityProviderException::clientException($response, $data);
        } elseif (isset($data['error'])) {
            throw CamdramIdentityProviderException::oauthException($response, $data);
        }
    }
    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     * @return \League\OAuth2\Client\Provider\ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new CamdramUser($response);
    }
    
    /**
     * Returns the string that should be used to separate scopes when building
     * the URL for requesting an access token.
     *
     * @return string Scope separator
     */
    protected function getScopeSeparator()
    {
        return ' ';
    }
}
