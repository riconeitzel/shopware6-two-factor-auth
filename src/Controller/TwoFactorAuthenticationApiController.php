<?php

declare(strict_types=1);

namespace RuneLaenen\TwoFactorAuth\Controller;

use RuneLaenen\TwoFactorAuth\Service\ConfigurationService;
use RuneLaenen\TwoFactorAuth\Service\TimebasedOneTimePasswordServiceInterface;
use Shopware\Components\Routing\RouterInterface;
use Symfony\Bundle\FrameworkBundle\Controller\Controller;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\Route;

class TwoFactorAuthenticationApiController extends Controller
{
    private $totpService;
    private $router;
    private $configurationService;

    public function __construct(
        TimebasedOneTimePasswordServiceInterface $totpService,
        RouterInterface $router,
        ConfigurationService $configurationService
    ) {
        $this->totpService = $totpService;
        $this->router = $router;
        $this->configurationService = $configurationService;
    }

    /**
     * @Route("/api/_action/rl-2fa/generate-secret", name="api.action.rl-2fa.generate-secret", methods={"GET"})
     */
    public function generateSecret(Request $request): JsonResponse
    {
        $company = $this->configurationService->getAdministrationCompany(
            $request->attributes->get('salesChannelId')
        );

        $secret = $this->totpService->createSecret();
        $qrUrl = $this->totpService->getQrCodeUrl(
            $company,
            $request->get('holder', ''),
            $secret
        );

        return new JsonResponse([
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
     * @Route("/api/_action/rl-2fa/validate-secret", name="api.action.rl-2fa.validate-secret", methods={"POST"})
     */
    public function validateSecret(Request $request): JsonResponse
    {
        if (empty($request->get('secret')) || empty($request->get('code'))) {
            return new JsonResponse([
                'status' => 'error',
                'error' => 'Secret or code empty',
            ], 400);
        }

        $verified = $this->totpService->verifyCode(
            (string) $request->get('secret'),
            (string) $request->get('code')
        );

        if ($verified) {
            return new JsonResponse([
                'status' => 'OK',
            ]);
        }

        return new JsonResponse([
            'status' => 'error',
            'error' => 'Secret and code not correct',
        ], Response::HTTP_BAD_REQUEST);
    }
}
