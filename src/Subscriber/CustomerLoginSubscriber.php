<?php

declare(strict_types=1);

namespace RuneLaenen\TwoFactorAuth\Subscriber;

use RuneLaenen\TwoFactorAuth\Event\StorefrontTwoFactorAuthEvent;
use RuneLaenen\TwoFactorAuth\Event\StorefrontTwoFactorCancelEvent;
use Shopware\Components\DependencyInjection\Container;
use Shopware\Components\Routing\RouterInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\FilterControllerEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class CustomerLoginSubscriber implements EventSubscriberInterface
{
    public const SESSION_NAME = 'RL_2FA_NEED_VERIFICATION';

    public function __construct(
        private readonly RequestStack $requestStack,
        private readonly RouterInterface $router
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            'Shopware_Modules_Admin_Login_Successful' => 'onCustomerLoginEvent',
            KernelEvents::CONTROLLER => 'onController',
            StorefrontTwoFactorAuthEvent::class => 'removeSession',
            StorefrontTwoFactorCancelEvent::class => 'removeSession',
        ];
    }

    public function onController(FilterControllerEvent $event): void
    {
        if (!$this->requestStack->getSession()->has(self::SESSION_NAME)) {
            return;
        }

        if (!$event->isMasterRequest()) {
            return;
        }

        if ($event->getRequest()->isXmlHttpRequest()) {
            return;
        }

        if (!$event->getRequest()->attributes->get('isShopwareStorefrontRequest')) {
            return;
        }

        if (\in_array($event->getRequest()->get('_route'), [
            'frontend.rl2fa.verification',
            'frontend.rl2fa.verification.cancel',
        ], true)) {
            return;
        }

        $queries = $event->getRequest()->query;
        $parameters = [];

        if ($queries->has('redirectTo')) {
            $parameters['redirect'] = $queries->all();
        }

        $url = $this->router->generate('frontend.rl2fa.verification', $parameters);

        $response = new RedirectResponse($url);

        $response->send();
    }

    public function onCustomerLoginEvent(): void
    {
        $customer = Shopware()->Modules()->Admin()->sGetUserData();

        if (empty($customer['additional']['user']['rl_2fa_secret'])) {
            return;
        }

        $this->requestStack->getSession()->set(self::SESSION_NAME, true);
    }

    public function removeSession(): void
    {
        $this->requestStack->getSession()->remove(self::SESSION_NAME);
    }
}
