<?php

namespace BeedooEdtech\Passport\Strategy;

use League\OAuth2\Client\Provider\Google;
use BeedooEdtech\Passport\Strategy\Strategy;

class AbstractGoogle
{
    /** @var array */
    protected $credential = [];

    protected $accessToken;

    /** @var \League\OAuth2\Client\Provider\Google */
    protected $provider;


    /** @var League\OAuth2\Client\Provider\GoogleUser $ownerDetails */
    protected $ownerDetails;

    protected $id;
    protected $name;
    protected $firstName;
    protected $lastName;
    protected $email;
    protected $avatar;

    public function __construct(string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->buildCredentialSettings($clientId, $clientSecret, $redirectUri);

        $this->provider = new Google($this->credential);
    }

    public function redirect(): void
    {
        if (empty($_GET['code'])) {
            $authUrl = $this->provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $this->provider->getState();

            header('Location: ' . $authUrl);
            exit;
        }
    }

    private function buildCredentialSettings(string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->credential = [
            "clientId" => $clientId,
            "clientSecret" => $clientSecret,
            "redirectUri" => $redirectUri,
        ];
    }

    protected function authorize()
    {
        if (!empty($_GET['error'])) {
            // Got an error, probably user denied access
            exit('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));

        } elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
            // State is invalid, possible CSRF attack in progress
            unset($_SESSION['oauth2state']);
            exit('Invalid state');
        
        } else {
            $this->accessToken = $this->provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
        
            try {
                $this->ownerDetails = $this->provider->getResourceOwner($this->accessToken);
            } catch (\Exception $e) {
                exit('Something went wrong: ' . $e->getMessage());
            }
        }
    }
}
