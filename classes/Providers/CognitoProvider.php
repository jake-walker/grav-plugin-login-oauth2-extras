<?php
namespace Grav\Plugin\Login\OAuth2\Providers;

use Grav\Common\Grav;
use GuzzleHttp\Promise;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;

class CognitoProvider extends ExtraProvider
{
    protected $name = 'Cognito';
    protected $classname = 'CakeDC\\OAuth2\\Client\\Provider\\Cognito';

    public function initProvider(array $options): void
    {
        $options += [
            'clientId'      => $this->config->get('providers.cognito.client_id'),
            'clientSecret'  => $this->config->get('providers.cognito.client_secret'),
            'redirectUri'   => $this->getCallbackUri(),
            'hostedDomain'  => $this->config->get('providers.cognito.domain')
        ];

        parent::initProvider($options);
    }

    public function getAuthorizationUrl()
    {
        $options = ['state' => $this->state];
        $options['scope'] = $this->config->get('providers.cognito.options.scope');

        return $this->provider->getAuthorizationUrl($options);
    }

    public function getUserData($user)
    {
        $data_user = [
            'id'         => $user->getId(),
            'login'      => $user->getUsername(),
            'email'      => $user->getEmail(),
            'fullname'   => $user->getName(),
            'cognito'    => $user->toArray()
        ];

        return $data_user;
    }
}
