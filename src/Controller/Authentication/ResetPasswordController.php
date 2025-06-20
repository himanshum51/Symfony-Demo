<?php

namespace App\Controller\Authentication;

use App\Entity\User;
use App\Service\OtpService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;

/**
 * Handles reset password logic after OTP verification.
 */
class ResetPasswordController extends AbstractController
{
    #[Route('/reset-password', name: 'app_reset_password', methods: ['GET', 'POST'])]
    public function resetPassword(
        Request $request,
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
        LoggerInterface $logger
    ): Response {
        $email = $request->query->get('email');

        if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $logger->warning('Invalid email provided for reset password.');
            return $this->render('auth/reset_password.html.twig', [
                'error' => 'Valid email is required.',
            ]);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $logger->warning('Reset password attempted for non-existent email: ' . $email);
            return $this->render('auth/reset_password.html.twig', [
                'error' => 'User not found.',
            ]);
        }

        if ($request->isMethod('POST')) {
            $newPassword = $request->request->get('password');

            if (!$newPassword) {
                $logger->warning('Invalid input for reset password.');
                return $this->render('auth/reset_password.html.twig', [
                    'error' => 'New password is required.',
                ]);
            }

            try {
                $user->setPassword($passwordHasher->hashPassword($user, $newPassword));
                $entityManager->persist($user);
                $entityManager->flush();

                $logger->info('Password reset successfully for email: ' . $email);
                return $this->render('auth/reset_password.html.twig', [
                    'success' => 'Password reset successfully.',
                ]);
            } catch (\Exception $e) {
                $logger->error('Failed to reset password for email: ' . $email . '. Error: ' . $e->getMessage());
                return $this->render('auth/reset_password.html.twig', [
                    'error' => 'Failed to reset password. Please try again later.',
                ]);
            }
        }

        return $this->render('auth/reset_password.html.twig', ['email' => $email]);
    }

     #[Route('/api/reset-password', name: 'api_reset_password', methods: ['POST'])]
    public function apiResetPassword(
        Request $request,
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
        OtpService $otpService,
        LoggerInterface $logger
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? null;
        $newPassword = $data['password'] ?? null;
        $token = $data['token'] ?? null;

        if (!$email || !$newPassword || !$token) {
            $logger->warning('Invalid input for API reset password.');
            return new JsonResponse(['error' => 'Email, OTP, new password, and token are required.'], 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $logger->warning('Invalid email format for API reset password: ' . $email);
            return new JsonResponse(['error' => 'Invalid email format.'], 400);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $logger->warning('API reset password attempted for non-existent email: ' . $email);
            return new JsonResponse(['error' => 'User not found.'], 404);
        }

        try {
            // Validate token
            if ($user->getApiToken() !== $token) {
                $logger->warning('Invalid token provided for API reset password for email: ' . $email);
                return new JsonResponse(['error' => 'Invalid token.'], 400);
            }

            // if (!$otpService->validateOtp($user, $otpCode)) {
            //     $logger->warning('Invalid OTP provided for API reset password for email: ' . $email);
            //     return new JsonResponse(['error' => 'Invalid OTP.'], 400);
            // }

            $user->setPassword($passwordHasher->hashPassword($user, $newPassword));
            $user->setApiToken(null); // Invalidate the token after successful password reset
            $entityManager->persist($user);
            $entityManager->flush();

            $logger->info('Password reset successfully for API email: ' . $email);
            return new JsonResponse(['message' => 'Password reset successfully.'], 200);
        } catch (\Exception $e) {
            $logger->error('Failed to reset password for API email: ' . $email . '. Error: ' . $e->getMessage());
            return new JsonResponse(['error' => 'Failed to reset password. Please try again later.'], 500);
        }
    }
}
