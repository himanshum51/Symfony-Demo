<?php

namespace App\Controller\Authentication;

use App\Entity\User;
use App\Service\OtpService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;

/**
 * Handles forgot password logic with OTP verification.
 */
class ForgotPasswordController extends AbstractController
{
    #[Route('/forgot-password', name: 'app_forgot_password', methods: ['GET', 'POST'])]
    public function forgotPassword(
        Request $request,
        EntityManagerInterface $entityManager,
        OtpService $otpService,
        LoggerInterface $logger
    ): Response {
        if ($request->isMethod('POST')) {
            $email = $request->request->get('email');

            if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $logger->warning('Invalid email provided for forgot password.');
                return $this->render('auth/forgot_password.html.twig', [
                    'error' => 'Valid email is required.',
                ]);
            }

            $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
            if (!$user) {
                $logger->warning('Forgot password attempted for non-existent email: ' . $email);
                return $this->render('auth/forgot_password.html.twig', [
                    'error' => 'User not found.',
                ]);
            }

            try {
                $otpService->generateOtp($user);
                $logger->info('OTP generated for forgot password request for email: ' . $email);
                return $this->render('auth/verify_otp.html.twig', [
                    'email' => $email,
                    'success' => 'OTP sent to your email. Please verify it.',
                ]);
            } catch (\Exception $e) {
                $logger->error('Failed to generate OTP for forgot password: ' . $e->getMessage());
                return $this->render('auth/forgot_password.html.twig', [
                    'error' => 'Failed to send OTP. Please try again later.',
                ]);
            }
        }

        return $this->render('auth/forgot_password.html.twig');
    }

    #[Route('/verify-otp', name: 'app_verify_otp', methods: ['GET', 'POST'])]
    public function verifyOtp(
        Request $request,
        EntityManagerInterface $entityManager,
        OtpService $otpService,
        LoggerInterface $logger
    ): Response {
        if ($request->isMethod('POST')) {
            $email = $request->request->get('email');
            $otpCode = $request->request->get('otp');

            if (!$email || !$otpCode) {
                $logger->warning('Invalid input for OTP verification.');
                return $this->render('auth/verify_otp.html.twig', [
                    'error' => 'Email and OTP are required.',
                ]);
            }

            $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
            if (!$user) {
                $logger->warning('OTP verification attempted for non-existent email: ' . $email);
                return $this->render('auth/verify_otp.html.twig', [
                    'error' => 'User not found.',
                ]);
            }

            try {
                if (!$otpService->validateOtp($user, $otpCode)) {
                    $logger->warning('Invalid OTP provided for email: ' . $email);
                    return $this->render('auth/verify_otp.html.twig', [
                        'error' => 'Invalid OTP.',
                    ]);
                }

                $logger->info('OTP verified successfully for email: ' . $email);
                return $this->redirectToRoute('app_reset_password', ['email' => $email]);
            } catch (\Exception $e) {
                $logger->error('Failed to verify OTP for email: ' . $email . '. Error: ' . $e->getMessage());
                return $this->render('auth/verify_otp.html.twig', [
                    'error' => 'Failed to verify OTP. Please try again later.',
                ]);
            }
        }

        return $this->render('auth/verify_otp.html.twig');
    }

    #[Route('/api/forgot-password', name: 'api_forgot_password', methods: ['POST'])]
    public function apiForgotPassword(
        Request $request,
        EntityManagerInterface $entityManager,
        OtpService $otpService,
        LoggerInterface $logger
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? null;

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $logger->warning('Invalid email provided for API forgot password.');
            return new JsonResponse(['error' => 'Valid email is required.'], 400);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $logger->warning('API forgot password attempted for non-existent email: ' . $email);
            return new JsonResponse(['error' => 'User not found.'], 404);
        }

        try {
            $otpService->generateOtp($user);
            $logger->info('OTP generated for API forgot password request for email: ' . $email);
            return new JsonResponse(['message' => 'OTP sent to your email.'], 200);
        } catch (\Exception $e) {
            $logger->error('Failed to generate OTP for API forgot password: ' . $e->getMessage());
            return new JsonResponse(['error' => 'Failed to send OTP. Please try again later.'], 500);
        }
    }

   
}
