<?php declare(strict_types=1);

namespace RuneLaenen\TwoFactorAuth\Service;

use Shopware\Components\DependencyInjection\Container;
use Shopware\Components\Routing\RouterInterface;

class ConfigurationService
{
    public const CONFIGURATION_KEY = 'RuneLaenenTwoFactorAuth';

    public function __construct(
        private readonly Container $container
    ) {
    }

    public function getAdministrationCompany(?string $salesChannelId = null): string
    {
        return $this->container->get('config')->getByNamespace(
            self::CONFIGURATION_KEY . '.config.administrationCompany',
            $salesChannelId
        );
    }

    public function isStorefrontEnabled(?string $salesChannelId = null): bool
    {
        return $this->container->get('config')->getByNamespace(
            self::CONFIGURATION_KEY . '.config.storefrontEnabled',
            $salesChannelId
        );
    }

    public function getStorefrontCompany(?string $salesChannelId = null): string
    {
        return $this->container->get('config')->getByNamespace(
            self::CONFIGURATION_KEY . '.config.storefrontCompany',
            $salesChannelId
        );
    }
}
