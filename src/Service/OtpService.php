<?php

namespace App\Service;

use App\Entity\Otp;
use App\Entity\User;
use App\Repository\OtpRepository;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Service for generating and validating OTPs.
 */
class OtpService
{
    private EntityManagerInterface $entityManager;
    private OtpRepository $otpRepository;
    private EmailService $emailService;
    private LoggerInterface $logger;

    public function __construct(
        EntityManagerInterface $entityManager,
        OtpRepository $otpRepository,
        EmailService $emailService,
        LoggerInterface $logger
    ) {
        $this->entityManager = $entityManager;
        $this->otpRepository = $otpRepository;
        $this->emailService = $emailService;
        $this->logger = $logger;
    }

    /**
     * Generates and sends an OTP for the user.
     *
     * @param User $user
     * @return Otp
     */
    public function generateOtp(User $user): Otp
    {
        $existingOtp = $this->otpRepository->findOneBy(['user' => $user]);

        // Delete existing OTP if it exists
        if ($existingOtp) {
            $this->entityManager->remove($existingOtp);
            $this->entityManager->flush();
            $this->logger->info('Existing OTP deleted for user: ' . $user->getEmail());
        }

        $otp = new Otp();
        $otp->setUser($user);
        $otp->setCode(sprintf('%06d', mt_rand(100000, 999999)));
        $otp->setAttempts(0);

        $this->entityManager->persist($otp);
        $this->entityManager->flush();

        try {
            $this->logger->info('Attempting to send OTP email to: ' . $user->getEmail());
            $this->emailService->sendOtpEmail($user->getEmail(), $otp->getCode());
            $this->logger->info('OTP email sent successfully to: ' . $user->getEmail());
        } catch (\Exception $e) {
            $this->logger->error('Failed to send OTP email to: ' . $user->getEmail() . '. Error: ' . $e->getMessage());
            throw $e;
        }

        $this->logger->info('OTP generated for user: ' . $user->getEmail());
        return $otp;
    }

    /**
     * Validates an OTP code.
     *
     * @param User $user
     * @param string $code
     * @return bool
     */
    public function validateOtp(User $user, string $code): bool
    {
        $otp = $this->otpRepository->findOneBy(['user' => $user]);

        if (!$otp) {
            $this->logger->warning('No OTP found for user: ' . $user->getEmail());
            return false;
        }

        if ($otp->getAttempts() >= 3) {
            $this->logger->warning('Too many OTP attempts for user: ' . $user->getEmail());
            throw new \Exception('Too many attempts. Please try again after 1 hour.');
        }

        if ($otp->getExpiresAt() < new \DateTime()) {
            $this->logger->warning('Expired OTP for user: ' . $user->getEmail());
            throw new \Exception('OTP has expired.');
        }

        if ($otp->getCode() !== $code) {
            $otp->setAttempts($otp->getAttempts() + 1);
            $otp->setLastAttemptAt(new \DateTime());
            $this->entityManager->persist($otp);
            $this->entityManager->flush();
            $this->logger->warning('Invalid OTP code for user: ' . $user->getEmail());
            return false;
        }

        $user->setIsOtpVerified(true);
        $this->entityManager->remove($otp);
        $this->entityManager->persist($user);
        $this->entityManager->flush();
        $this->logger->info('OTP validated successfully for user: ' . $user->getEmail());

        return true;
    }
}