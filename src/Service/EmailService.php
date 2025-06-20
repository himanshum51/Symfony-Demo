<?php

namespace App\Service;

use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mime\Email;
use Psr\Log\LoggerInterface;

/**
 * Service for sending emails, such as OTP verification emails.
 */
class EmailService
{
    private MailerInterface $mailer;
    private LoggerInterface $logger;
    private string $fromEmail;

    public function __construct(
        MailerInterface $mailer,
        LoggerInterface $logger,
        string $fromEmail
    ) {
        $this->mailer = $mailer;
        $this->logger = $logger;
        $this->fromEmail = $fromEmail;
    }

    /**
     * Sends an OTP email to the user.
     *
     * @param string $recipientEmail Recipient email address
     * @param string $otpCode OTP code
     * @return void
     * @throws TransportExceptionInterface
     */
    public function sendOtpEmail(string $recipientEmail, string $otpCode): void
    {
        try {
            $this->logger->debug('Mailer DSN: ' . (getenv('MAILER_DSN') ?: 'Not set'));
            $this->logger->debug('Sender email: ' . $this->fromEmail);

            $email = (new Email())
                ->from($this->fromEmail)
                ->to($recipientEmail)
                ->subject('Your OTP Code')
                ->text('Your OTP code is: ' . $otpCode . '. It is valid for 2 minutes.')
                ->html("<p>Your OTP code is: <strong>$otpCode</strong>. It is valid for 2 minutes.</p>");

            $this->logger->debug('Email details: ' . $email->toString());
            $this->mailer->send($email);
            $this->logger->info('OTP email sent successfully to: ' . $recipientEmail);
        } catch (TransportExceptionInterface $e) {
            $this->logger->error('Failed to send OTP email to: ' . $recipientEmail . '. Error: ' . $e->getMessage());
            throw new \Exception('Failed to send OTP email: ' . $e->getMessage());
        }
    }
}