<?php

namespace BeedooEdtech\Passport\Strategy;

use BeedooEdtech\Passport\Strategy\Strategy;
use League\OAuth2\Client\Provider\Google;

class GoogleStrategy implements Strategy
{
    /** @var array */
    private $credential = [];

    /** @var \League\OAuth2\Client\Provider\Google */
    private $provider;

    private $id;
    private $name;
    private $firstName;
    private $lastName;
    private $email;
    private $avatar;

    public function __construct(string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->buildCredentialSettings($clientId, $clientSecret, $redirectUri);

        $this->provider = new Google($this->credential);
    }

    public function auth(): void
    {
        if (empty($_GET['code'])) {
            $authUrl = $this->provider->getAuthorizationUrl();
            $_SESSION['oauth2state'] = $this->provider->getState();

            header('Location: ' . $authUrl);
            exit;
        }

        $this->validate();
    }

    private function buildCredentialSettings(string $clientId, string $clientSecret, string $redirectUri)
    {
        $this->credential = [
            "clientId" => $clientId,
            "clientSecret" => $clientSecret,
            "redirectUri" => $redirectUri,
        ];
    }

    private function validate()
    {
        if (!empty($_GET['error'])) {
            // Got an error, probably user denied access
            exit('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));

        } elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {
            // State is invalid, possible CSRF attack in progress
            unset($_SESSION['oauth2state']);
            exit('Invalid state');
        
        } else {
            // Try to get an access token (using the authorization code grant)
            $token = $this->provider->getAccessToken('authorization_code', [
                'code' => $_GET['code']
            ]);
        
            try {
                /** @var League\OAuth2\Client\Provider\GoogleUser $ownerDetails */
                $ownerDetails = $this->provider->getResourceOwner($token);
        
                $this->setId($ownerDetails);
                $this->setName($ownerDetails);
                $this->setFirstName($ownerDetails);
                $this->setLastName($ownerDetails);
                $this->setEmail($ownerDetails);
                $this->setAvatar($ownerDetails);

            } catch (\Exception $e) {
                exit('Something went wrong: ' . $e->getMessage());
            }
        }
    }

    public function getId()
    {
        return $this->id;
    }

    public function getName()
    {
        return $this->name;
    }

    public function getFirstName()
    {
        return $this->firstName;
    }

    public function getLastName()
    {
        return $this->lastName;
    }

    public function getEmail()
    {
        return $this->email;
    }

    public function getAvatar()
    {
        return $this->avatar;
    }

    public function setId($provider)
    {
        $this->id = $provider->getId();
    }

    public function setName($provider)
    {
        $this->name = $provider->getName();
    }

    public function setFirstName($provider)
    {
        $this->firstName = $provider->getFirstName();
    }

    public function setLastName($provider)
    {
        $this->lastName = $provider->getLastName();
    }

    public function setEmail($provider)
    {
        $this->email = $provider->getEmail();
    }
    
    public function setAvatar($provider)
    {
        $this->avatar = $provider->getAvatar();
    }

}
