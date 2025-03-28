<?php declare(strict_types=1);

namespace RuneLaenen\TwoFactorAuth\Controller;

use RuneLaenen\TwoFactorAuth\Service\ConfigurationService;
use RuneLaenen\TwoFactorAuth\Service\TimebasedOneTimePasswordServiceInterface;
use Shopware\Components\DependencyInjection\Container;
use Shopware\Components\Routing\RouterInterface;
use Shopware\Models\Customer\Customer;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class TwoFactorAuthenticationController extends Controller
{
    private $configurationService;
    private $totpService;
    private $router;
    private $customerRepository;
    private $legacyPasswordVerifier;

    public function __construct(
        ConfigurationService $configurationService,
        TimebasedOneTimePasswordServiceInterface $totpService,
        RouterInterface $router,
        $customerRepository,
        $legacyPasswordVerifier
    ) {
        $this->configurationService = $configurationService;
        $this->totpService = $totpService;
        $this->router = $router;
        $this->customerRepository = $customerRepository;
        $this->legacyPasswordVerifier = $legacyPasswordVerifier;
    }

    /**
     * @Route("/rl-2fa/profile/setup", name="widgets.rl-2fa.profile.setup", defaults={"XmlHttpRequest"=true}, methods={"GET"})
     */
    public function profileSetup(Request $request): Response
    {
        $customer = $this->getUser();
        $salesChannelId = $request->get('salesChannelId');

        if ($customer === null || !$this->configurationService->isStorefrontEnabled($salesChannelId)) {
            return new Response();
        }

        $company = $this->configurationService->getStorefrontCompany(
            $salesChannelId
        );

        $secret = $this->totpService->createSecret();

        $qrUrl = $this->totpService->getQrCodeUrl(
            $company,
            $customer->getFirstName() . ' ' . $customer->getLastName(),
            $secret
        );

        return $this->render('@Storefront/storefront/page/account/profile/2fa/setup.html.twig', [
            'secret' => $secret,
            'qrUrl' => $this->router->generate(
                'rl-2fa.qr-code.secret',
                [
                    'qrUrl' => $qrUrl,
                ],
                UrlGeneratorInterface::ABSOLUTE_URL
            ),
        ]);
    }

    /**
     * @Route("/rl-2fa/profile/disable", name="widgets.rl-2fa.profile.disable", defaults={"XmlHttpRequest"=true}, methods={"GET"})
     */
    public function profileDisable(Request $request): Response
    {
        $salesChannelId = $request->get('salesChannelId');

        if (!$this->configurationService->isStorefrontEnabled($salesChannelId)) {
            return new Response();
        }

        return $this->render('@Storefront/storefront/page/account/profile/2fa/disable.html.twig');
    }

    /**
     * @Route("/rl-2fa/profile/disable", name="widgets.rl-2fa.profile.disable.post", defaults={"XmlHttpRequest"=true}, methods={"POST"})
     */
    public function profileDisablePost(Request $request): Response
    {
        if (!$this->configurationService->isStorefrontEnabled($request->get('salesChannelId'))) {
            $this->addFlash('danger', $this->trans('rl-2fa.account.error.not-enabled'));

            return $this->redirectToRoute('frontend.account.profile.page');
        }

        $customer = $this->getUser();
        $password = $request->get('otpPassword');
        if (!$customer) {
            $this->addFlash('danger', $this->trans('rl-2fa.account.error.no-customer'));

            return $this->redirectToRoute('frontend.account.profile.page');
        }

        if ($customer->hasLegacyPassword()) {
            if (!$this->legacyPasswordVerifier->verify($password, $customer)) {
                $this->addFlash('danger', $this->trans('rl-2fa.account.error.incorrect-password'));

                return $this->redirectToRoute('frontend.account.profile.page');
            }
        } else {
            if (!password_verify($password, $customer->getPassword())) {
                $this->addFlash('danger', $this->trans('rl-2fa.account.error.incorrect-password'));

                return $this->redirectToRoute('frontend.account.profile.page');
            }
        }

        $this->customerRepository->update([
            [
                'id' => $customer->getId(),
                'customFields' => [
                    'rl_2fa_secret' => '',
                ],
            ],
        ], $this->get('shopware.context'));

        $this->addFlash('info', $this->trans('rl-2fa.account.disabled-2fa'));

        return $this->redirectToRoute('frontend.account.profile.page');
    }

    /**
     * @Route("/rl-2fa/profile/validate", name="widgets.rl-2fa.profile.validate", methods={"POST"}, defaults={"XmlHttpRequest"=true})
     */
    public function validateSecret(Request $request): Response
    {
        if (!$this->configurationService->isStorefrontEnabled($request->get('salesChannelId'))) {
            return new JsonResponse([
                'status' => 'error',
                'error' => $this->trans('rl-2fa.account.error.not-enabled'),
            ], 400);
        }

        if (!$this->getUser()) {
            return new JsonResponse([
                'status' => 'error',
                'error' => $this->trans('rl-2fa.account.error.no-customer'),
            ], 400);
        }

        if (empty($request->get('secret')) || empty($request->get('code'))) {
            return new JsonResponse([
                'status' => 'error',
                'error' => $this->trans('rl-2fa.account.error.empty-input'),
            ], 400);
        }

        $verified = $this->totpService->verifyCode(
            (string) $request->get('secret'),
            (string) $request->get('code')
        );

        if ($verified) {
            $this->customerRepository->update([
                [
                    'id' => $this->getUser()->getId(),
                    'customFields' => [
                        'rl_2fa_secret' => (string) $request->get('secret'),
                    ],
                ],
            ], $this->get('shopware.context'));

            return new JsonResponse([
                'status' => 'OK',
            ]);
        }

        return new JsonResponse([
            'status' => 'error',
            'error' => $this->trans('rl-2fa.account.error.incorrect-code'),
        ]);
    }
}
