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
        return $this->ownerDetails->getId();
    }

    public function getName()
    {
        return $this->ownerDetails->getName();
    }

    public function getFirstName()
    {
        return $this->ownerDetails->getFirstName();
    }

    public function getLastName()
    {
        return $this->ownerDetails->getLastName();
    }

    public function getEmail()
    {
        return $this->ownerDetails->getEmail();
    }

    public function getAvatar()
    {
        return $this->ownerDetails->getAvatar();
    }
}
