<?php

namespace App\Controller\Authentication;

use App\Entity\TokenBlacklist;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;

/**
 * Handles user logout for API.
 */
class LogoutController extends AbstractController
{
    #[Route('/api/logout', name: 'app_api_logout', methods: ['POST'])]
    public function apiLogout(
        Request $request,
        EntityManagerInterface $entityManager,
        JWTTokenManagerInterface $jwtManager,
        LoggerInterface $logger
    ): JsonResponse {
        $authHeader = $request->headers->get('Authorization');
        if (!$authHeader || !preg_match('/Bearer\s(\S+)/', $authHeader, $matches)) {
            $logger->warning('API logout failed: No valid JWT token provided.');
            return new JsonResponse(['error' => 'Invalid or missing token.'], 401);
        }

        $token = $matches[1];

        try {
            $decoded = $jwtManager->parse($token);
            $expiresAt = new \DateTimeImmutable('@' . $decoded['exp']);
        } catch (\Exception $e) {
            $logger->warning('API logout failed: Invalid JWT token - ' . $e->getMessage());
            return new JsonResponse(['error' => 'Invalid token.'], 401);
        }

        $blacklistRepo = $entityManager->getRepository(TokenBlacklist::class);
        if ($blacklistRepo->findOneBy(['token' => $token])) {
            $logger->info('API logout attempted with already blacklisted token.');
            return new JsonResponse(['message' => 'Logout successful.'], 200);
        }

        $blacklistedToken = new TokenBlacklist();
        $blacklistedToken->setToken($token);
        $blacklistedToken->setExpiresAt($expiresAt);

        $entityManager->persist($blacklistedToken);
        $entityManager->flush();

        $logger->info('API logout successful: Token blacklisted.');

        return new JsonResponse(['message' => 'Logout successful.'], 200);
    }
}