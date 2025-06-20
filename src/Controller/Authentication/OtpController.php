<?php

namespace App\Controller\Authentication;

use App\Entity\User;
use App\Service\OtpService;
use Doctrine\ORM\EntityManagerInterface;
use Nelmio\ApiDocBundle\Annotation\Model;
use Nelmio\ApiDocBundle\Annotation\Security;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;

/**
 * Handles OTP verification for both web and API.
 */
class OtpController extends AbstractController
{
    #[Route('/otp', name: 'app_otp_verify', methods: ['GET', 'POST'])]
    public function verifyOtp(
        Request $request,
        OtpService $otpService,
        SessionInterface $session,
        EntityManagerInterface $entityManager,
        LoggerInterface $logger
    ): Response {
        $userId = $session->get('pending_user_id');
        if (!$userId) {
            $logger->warning('No pending_user_id found in session for OTP verification.');
            return $this->redirectToRoute('app_register');
        }

        $user = $entityManager->getRepository(User::class)->find($userId);
        if (!$user) {
            $logger->error('User not found for ID: ' . $userId);
            $session->remove('pending_user_id');
            return $this->redirectToRoute('app_register');
        }

        if ($request->isMethod('POST')) {
            $otpCode = $request->request->get('otp');

            if (!$otpCode) {
                $logger->warning('No OTP code provided for user: ' . $user->getEmail());
                return $this->render('auth/otp.html.twig', [
                    'error' => 'OTP code is required.',
                ]);
            }

            try {
                if ($otpService->validateOtp($user, $otpCode)) {
                    $logger->info('OTP verified successfully for user: ' . $user->getEmail());
                    $session->remove('pending_user_id');
                    return $this->redirectToRoute('app_login');
                } else {
                    $logger->warning('Invalid OTP code provided for user: ' . $user->getEmail());
                    return $this->render('auth/otp.html.twig', [
                        'error' => 'Invalid OTP code.',
                    ]);
                }
            } catch (\Exception $e) {
                $logger->error('OTP verification failed: ' . $e->getMessage());
                return $this->render('auth/otp.html.twig', [
                    'error' => $e->getMessage(),
                ]);
            }
        }

        return $this->render('auth/otp.html.twig');
    }

    #[Route('/api/otp', name: 'api_otp_verify', methods: ['POST'])]
    public function apiVerifyOtp(
        Request $request,
        OtpService $otpService,
        EntityManagerInterface $entityManager,
        LoggerInterface $logger
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? null;
        $otpCode = $data['otp'] ?? null;

        if (!$email || !$otpCode) {
            $logger->warning('Invalid input for API OTP verification.');
            return new JsonResponse(['error' => 'Email and OTP are required.'], 400);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $logger->warning('API OTP verification attempted for non-existent email: ' . $email);
            return new JsonResponse(['error' => 'User not found.'], 404);
        }

        try {
            if (!$otpService->validateOtp($user, $otpCode)) {
                $logger->warning('Invalid OTP provided for API OTP verification for email: ' . $email);
                return new JsonResponse(['error' => 'Invalid OTP.'], 400);
            }

            // Generate token after successful OTP verification
            $token = bin2hex(random_bytes(32)); // Example token generation
            $user->setApiToken($token); // Assuming `setApiToken` exists in the User entity
            $entityManager->persist($user);
            $entityManager->flush();

            $logger->info('OTP verified successfully for API email: ' . $email);
            return new JsonResponse([
                'message' => 'OTP verified successfully.',
                'token' => $token // Include token in the response
            ], 200);
        } catch (\Exception $e) {
            $logger->error('Failed to verify OTP for API email: ' . $email . '. Error: ' . $e->getMessage());
            return new JsonResponse(['error' => 'Failed to verify OTP. Please try again later.'], 500);
        }
    }
}