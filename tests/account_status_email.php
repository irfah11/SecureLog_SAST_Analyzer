<?php
// Inject a non-network mailer. No email is sent and no account is updated.
require_once __DIR__ . '/../Notification/NotificationService.php';

class CapturedStatusMailer extends PHPMailer\PHPMailer\PHPMailer
{
    public int $attempts = 0;
    public bool $accept = true;
    public function send(): bool
    {
        $this->attempts++;
        if (!$this->accept) return false;
        return $this->preSend(); // Compose and validate MIME only, no SMTP connection.
    }
}
$assert = static function (bool $ok, string $message): void {
    if (!$ok) throw new RuntimeException($message);
    echo "PASS: {$message}\n";
};
// Synthetic credentials prevent real values from appearing in diagnostic output.
$config = ['smtp_host' => 'smtp.gmail.com', 'smtp_port' => 587,
    'smtp_username' => ' sender@example.test ', 'smtp_password' => 'abcd efgh ijkl mnop',
    'from_email' => 'sender@example.test', 'from_name' => 'SecureLog'];
$approved = new CapturedStatusMailer(true);
$assert(sendAccountStatusNotification('recipient@example.test', '<b>Test & User</b>', true, $approved), 'Approved email composes successfully');
$assert($approved->Mailer === 'smtp' && $approved->SMTPAuth && $approved->Port === 587
    && $approved->SMTPSecure === PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS, 'Approved email uses authenticated STARTTLS SMTP');
$assert($approved->Username === 'sender@example.test' && strlen($approved->Password) === 16, 'Gmail display whitespace is normalized');
$assert($approved->Subject === 'SecureLog Account Approved', 'Approved account uses approval subject');
$assert(str_contains($approved->Body, '&lt;b&gt;Test &amp; User&lt;/b&gt;'), 'Recipient name is escaped in approved HTML');
$assert($approved->attempts === 1, 'Only one delivery attempt is made');
$pending = new CapturedStatusMailer(true);
$assert(sendAccountStatusNotification('recipient@example.test', '<b>Test & User</b>', false, $pending), 'Pending email composes successfully');
$assert($pending->Mailer === 'smtp' && $pending->SMTPAuth, 'Pending email also uses authenticated SMTP');
$assert($pending->Subject === 'SecureLog Registration Status'
    && str_contains($pending->AltBody, 'pending administrator approval'), 'Pending message does not claim account approval');
$assert(str_contains($pending->Body, '&lt;b&gt;Test &amp; User&lt;/b&gt;'), 'Recipient name is escaped in pending HTML');
$assert(count($pending->getToAddresses()) === 1 && $pending->getToAddresses()[0][0] === 'recipient@example.test', 'Notification has only the selected recipient');
$failed = new CapturedStatusMailer(true); $failed->accept = false;
$assert(!sendAccountStatusNotification('recipient@example.test', 'Test', true, $failed), 'Approved transport failure is not reported as success');
$failedPending = new CapturedStatusMailer(true); $failedPending->accept = false;
$assert(!sendAccountStatusNotification('recipient@example.test', 'Test', false, $failedPending), 'Pending transport failure is not reported as success');
$config['smtp_host'] = 'smtp.example.test'; $config['smtp_password'] = 'password with spaces';
$other = new CapturedStatusMailer(true);
configureSecureLogStatusMailer($other);
$assert($other->Password === 'password with spaces', 'Non-Gmail passwords are preserved');
$controller = file_get_contents(__DIR__ . '/../ManageUser/editUser.php');
$assert(str_contains($controller, 'sendAccountStatusNotification(') && !preg_match('/\bmail\s*\(/', $controller), 'Edit User uses the shared service instead of PHP mail');
