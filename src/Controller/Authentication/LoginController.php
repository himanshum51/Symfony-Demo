<?php

namespace App\Controller\Authentication;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Security\Http\Authentication\AuthenticationUtils;
use Psr\Log\LoggerInterface;

/**
 * Handles user login for both web and API.
 */
class LoginController extends AbstractController
{
    #[Route('/login', name: 'app_login', methods: ['GET', 'POST'])]
public function login(
    Request $request,
    AuthenticationUtils $authenticationUtils,
    EntityManagerInterface $entityManager,
    UserPasswordHasherInterface $passwordHasher,
    JWTTokenManagerInterface $jwtManager
): Response {
    // If it's a POST request, handle the login form submission manually
    if ($request->isMethod('POST')) {
        $email = $request->request->get('email');
        $password = $request->request->get('password');

        if (!$email || !$password) {
            return $this->render('auth/login.html.twig', [
                'error' => 'Email and password are required.',
            ]);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

        if (!$user || !$passwordHasher->isPasswordValid($user, $password)) {
            return $this->render('auth/login.html.twig', [
                'error' => 'Invalid credentials.',
            ]);
        }

        if (!$user->isOtpVerified()) {
            return $this->render('auth/login.html.twig', [
                'error' => 'Please verify your OTP before logging in.',
            ]);
        }

        // Generate JWT token
        $token = $jwtManager->create($user);

        // Store JWT in a cookie (optional)
        $response = $this->redirectToRoute('app_home');
        $response->headers->setCookie(
            new \Symfony\Component\HttpFoundation\Cookie('BEARER', $token, 0, '/', null, false, true, false, 'Strict')
        );

        return $response;
    }

    // If it's a GET request, render the form
    $error = $authenticationUtils->getLastAuthenticationError();

    return $this->render('auth/login.html.twig', [
        'error' => $error ? $error->getMessage() : null,
    ]);
}

    #[Route('/home', name: 'app_home')]
    public function home(): Response
    {
        return $this->render('auth/home.html.twig');
    }

    #[Route('/logout', name: 'app_logout')]
    public function logout(): void
    {
        // Handled by Symfony Security
    }

    #[Route('/api/login', name: 'app_api_login', methods: ['POST'])]
    public function apiLogin(
        Request $request,
        EntityManagerInterface $entityManager,
        UserPasswordHasherInterface $passwordHasher,
        JWTTokenManagerInterface $jwtManager,
        LoggerInterface $logger
    ): JsonResponse {
        $data = json_decode($request->getContent(), true);
        $email = $data['email'] ?? null;
        $password = $data['password'] ?? null;

        if (!$email || !$password) {
            $logger->warning('Invalid input for API login: email or password missing.');
            return new JsonResponse(['error' => 'Email and password are required.'], 400);
        }

        $user = $entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user) {
            $logger->warning('API login failed: User not found for email: ' . $email);
            return new JsonResponse(['error' => 'Invalid credentials.'], 401);
        }

        if (!$passwordHasher->isPasswordValid($user, $password)) {
            $logger->warning('API login failed: Invalid password for email: ' . $email);
            return new JsonResponse(['error' => 'Invalid credentials.'], 401);
        }

        if (!$user->isOtpVerified()) {
            $logger->warning('API login failed: OTP not verified for email: ' . $email);
            return new JsonResponse(['error' => 'Please verify your OTP before logging in.'], 401);
        }

        $token = $jwtManager->create($user);
        $logger->info('API login successful for email: ' . $email);

        return new JsonResponse([
            'message' => 'Login successful.',
            'token' => $token,
        ], 200);
    }
}