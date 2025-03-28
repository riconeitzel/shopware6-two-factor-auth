<?php

declare(strict_types=1);

namespace RuneLaenen\TwoFactorAuth\Subscriber;

use League\OAuth2\Server\Exception\OAuthServerException;
use RuneLaenen\TwoFactorAuth\Service\TimebasedOneTimePasswordServiceInterface;
use Shopware\Components\DependencyInjection\Container;
use Shopware\Components\Routing\RouterInterface;
use Shopware\Models\User\User;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\FilterResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

class ApiOauthTokenSubscriber implements EventSubscriberInterface
{
    private $userRepository;
    private $oneTimePasswordService;

    public function __construct(
        Container $container,
        TimebasedOneTimePasswordServiceInterface $oneTimePasswordService
    ) {
        $this->userRepository = $container->get('models')->getRepository(User::class);
        $this->oneTimePasswordService = $oneTimePasswordService;
    }

    public static function getSubscribedEvents(): array
    {
        return [
            KernelEvents::RESPONSE => 'onResponse',
        ];
    }

    public function onResponse(FilterResponseEvent $event): void
    {
        $request = $event->getRequest();

        if ($request->attributes->get('_route') !== 'api.oauth.token') {
            return;
        }

        if ($request->request->get('scope') === 'user-verified'
            || $event->getResponse()->getStatusCode() !== 200) {
            return;
        }

        $username = $request->request->get('username');

        $user = $this->userRepository->findOneBy(['username' => $username]);

        if (!$user instanceof User
            || empty($user->getAttribute()->get('rl_2fa_secret'))
        ) {
            return;
        }

        $otp = $request->request->get('rl_2fa_otp');
        if ($otp && $this->checkOtp($user->getAttribute()->get('rl_2fa_secret'), $otp)) {
            return;
        }

        throw new OAuthServerException('This user needs an extra OTP', 1010, 'request-otp', 401, 'request-otp');
    }

    /**
     * @returns true if OTP is correct
     *
     * @throws OAuthServerException when the OTP is incorrect
     */
    private function checkOtp($secret, $code): bool
    {
        try {
            if (!$this->oneTimePasswordService->verifyCode($secret, $code)) {
                throw new \Exception();
            }
        } catch (\Exception $exception) {
            throw new OAuthServerException('Wrong OTP', 1011, 'wrong-otp', 401, null, null, $exception);
        }

        return true;
    }
}
