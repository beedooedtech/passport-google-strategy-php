<?php

namespace BeedooEdtech\Passport\Strategy;

use BeedooEdtech\Passport\Strategy\Strategy as StrategyInterface;

class GoogleStrategy extends AbstractGoogle implements StrategyInterface
{
    public function __construct(string $clientId, string $clientSecret, string $redirectUri)
    {
        parent::__construct($clientId, $clientSecret, $redirectUri);
    }

    public function getId()
    {
        $this->authorize();
        return $this->ownerDetails->getId();
    }

    public function getName()
    {
        $this->authorize();
        return $this->ownerDetails->getName();
    }

    public function getFirstName()
    {
        $this->authorize();
        return $this->ownerDetails->getFirstName();
    }

    public function getLastName()
    {
        $this->authorize();
        return $this->ownerDetails->getLastName();
    }

    public function getEmail()
    {
        $this->authorize();
        return $this->ownerDetails->getEmail();
    }

    public function getAvatar()
    {
        $this->authorize();
        return $this->ownerDetails->getAvatar();
    }
}
