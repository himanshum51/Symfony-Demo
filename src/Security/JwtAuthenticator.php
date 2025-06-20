<?php

namespace App\Security;

use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;

/**
 * Custom JWT authenticator for API routes.
 */
class JwtAuthenticator extends AbstractAuthenticator
{
    private JWTTokenManagerInterface $jwtManager;

    public function __construct(JWTTokenManagerInterface $jwtManager)
    {
        $this->jwtManager = $jwtManager;
    }

    public function supports(Request $request): ?bool
    {
        return $request->headers->has('Authorization') && str_starts_with($request->headers->get('Authorization'), 'Bearer ');
    }

    public function authenticate(Request $request): SelfValidatingPassport
    {
        $token = str_replace('Bearer ', '', $request->headers->get('Authorization'));
        try {
            $payload = $this->jwtManager->decode($token);
            if (!isset($payload['username'])) {
                throw new AuthenticationException('Invalid JWT token: username not found');
            }
            return new SelfValidatingPassport(new UserBadge($payload['username']));
        } catch (\Exception $e) {
            throw new AuthenticationException('Invalid JWT token: ' . $e->getMessage());
        }
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?JsonResponse
    {
        return null; // Continue to requested route
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?JsonResponse
    {
        return new JsonResponse(['message' => $exception->getMessage()], 401);
    }
}