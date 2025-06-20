<?php

namespace App\Controller\Authentication;

use App\Entity\User;
use App\Service\OtpService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Psr\Log\LoggerInterface;

/**
 * Handles user registration and OTP generation for both web and API.
 */
class RegisterController extends AbstractController
{
    private const PASSWORD_MIN_LENGTH = 8;
    private const PASSWORD_REGEX = '/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/';

    #[Route('/register', name: 'app_register', methods: ['GET', 'POST'])]
    public function register(
        Request $request,
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
        OtpService $otpService,
        SessionInterface $session,
        LoggerInterface $logger
    ): Response {
        if ($request->isMethod('POST')) {
            $email = $request->request->get('email');
            $password = $request->request->get('password');
            $rolesInput = $request->request->get('roles', 'ROLE_USER'); // Default to ROLE_USER
            $roles = is_array($rolesInput) ? $rolesInput : explode(',', $rolesInput); // Ensure roles are an array

            // Validate email and password
            if (!$email || !$password) {
                $logger->warning('Invalid input for registration: email or password missing.');
                return $this->render('auth/register.html.twig', [
                    'error' => 'Email and password are required.',
                ]);
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $logger->warning('Invalid email format: ' . $email);
                return $this->render('auth/register.html.twig', [
                    'error' => 'Invalid email format.',
                ]);
            }

            if (!preg_match(self::PASSWORD_REGEX, $password)) {
                $logger->warning('Weak password provided for email: ' . $email);
                return $this->render('auth/register.html.twig', [
                    'error' => 'Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character (@$!%*?&).',
                ]);
            }

            try {
                $session->start();
                $logger->info('Session started with ID: ' . $session->getId());

                if ($entityManager->getRepository(User::class)->findOneBy(['email' => $email])) {
                    $logger->warning('Registration attempted with existing email: ' . $email);
                    return $this->render('auth/register.html.twig', [
                        'error' => 'Email already exists.',
                    ]);
                }

                $user = new User();
                $user->setEmail($email);
                $user->setPassword($passwordHasher->hashPassword($user, $password));
                $user->setRoles($roles);
                $user->setIsOtpVerified(false);

                $entityManager->persist($user);
                $entityManager->flush();

                $otpService->generateOtp($user);
                $session->set('pending_user_id', $user->getId());
                $logger->info('User registered and OTP generated for: ' . $email . ', session ID set: ' . $user->getId());
                return $this->redirectToRoute('app_otp_verify');
            } catch (\Exception $e) {
                $logger->error('Registration failed for email: ' . $email . '. Error: ' . $e->getMessage());
                return $this->render('auth/register.html.twig', [
                    'error' => 'Registration failed: ' . ($e->getMessage() === 'Failed to send OTP email' ? 'Unable to send OTP email. Please try again.' : $e->getMessage()),
                ]);
            }
        }

        return $this->render('auth/register.html.twig');
    }

    #[Route('/api/register', name: 'api_register', methods: ['POST'])]
    public function apiRegister(
        Request $request,
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
        OtpService $otpService,
        SessionInterface $session,
        LoggerInterface $logger
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;
        $roles = $data['roles'] ?? ['ROLE_USER'];

        // Validate email and password
        if (!$email || !$password) {
            $logger->warning('Invalid input for API registration: email or password missing.');
            return new JsonResponse(['error' => 'Email and password are required.'], 400);
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $logger->warning('Invalid email format: ' . $email);
            return new JsonResponse(['error' => 'Invalid email format.'], 400);
        }

        if (!preg_match(self::PASSWORD_REGEX, $password)) {
            $logger->warning('Weak password provided for email: ' . $email);
            return new JsonResponse([
                'error' => 'Password must be at least 8 characters long and include uppercase, lowercase, a number, and a special character (@$!%*?&).'
            ], 400);
        }

        try {
            $session->start();
            $logger->info('Session started with ID: ' . $session->getId());

            if ($entityManager->getRepository(User::class)->findOneBy(['email' => $email])) {
                $logger->warning('Registration attempted with existing email: ' . $email);
                return new JsonResponse(['error' => 'Email already exists.'], 400);
            }

            $user = new User();
            $user->setEmail($email);
            $user->setPassword($passwordHasher->hashPassword($user, $password));
            $user->setRoles($roles);
            $user->setIsOtpVerified(false);

            $entityManager->persist($user);
            $entityManager->flush();

            $otpService->generateOtp($user);
            $session->set('pending_user_id', $user->getId());
            $logger->info('User registered and OTP generated for: ' . $email . ', session ID set: ' . $user->getId());

            return new JsonResponse(['message' => 'User registered. Please check your email for OTP.'], 201);
        } catch (\Exception $e) {
            $logger->error('API registration failed for email: ' . $email . '. Error: ' . $e->getMessage());
            return new JsonResponse([
                'error' => 'Registration failed: ' . ($e->getMessage() === 'Failed to send OTP email' ? 'Unable to send OTP email. Please try again.' : $e->getMessage())
            ], 400);
        }
    }
}