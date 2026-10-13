<?php
declare(strict_types=1);

/**
 * SecureLog Vault Cryptography Service
 *
 * Responsibilities:
 * - Generate and manage a 256-bit master encryption key.
 * - Encrypt sealed audit logs using AES-256-GCM.
 * - Authenticate protected archive metadata using AAD.
 * - Verify integrity/authenticity before decryption.
 *
 * SECURITY NOTES:
 * - Master key is NEVER stored inside a .slog archive.
 * - Master key is NEVER returned to the browser.
 * - A unique random IV/nonce is generated for every encryption.
 * - AES-GCM authentication tag detects modification.
 */

final class VaultCrypto
{
    /* ============================================================
       CRYPTOGRAPHIC CONFIGURATION
       ============================================================ */

    private const CIPHER = 'aes-256-gcm';

    /*
     * 32 bytes × 8 = 256 bits.
     */
    private const KEY_LENGTH_BYTES = 32;

    /*
     * AES-GCM authentication tag length.
     */
    private const TAG_LENGTH_BYTES = 16;

    /*
     * SecureLog encrypted archive format.
     */
    private const VAULT_FORMAT = 'SECURELOG_VAULT_V1';

    private const VAULT_VERSION = 1;

    private string $keyDirectory;
    private string $keyFile;


    /* ============================================================
       CONSTRUCTOR
       ============================================================ */

    public function __construct()
    {
        $this->keyDirectory =
            __DIR__
            . DIRECTORY_SEPARATOR
            . 'keys';

        $this->keyFile =
            $this->keyDirectory
            . DIRECTORY_SEPARATOR
            . 'master.key';
    }


    /* ============================================================
       MASTER KEY INITIALIZATION
       ============================================================ */

    /**
     * Create the SecureLog master encryption key.
     *
     * IMPORTANT:
     * An existing key is NEVER overwritten automatically.
     *
     * Replacing the key would make previously encrypted
     * SecureLog archives impossible to decrypt.
     */
    public function initializeKey(): bool
    {
        $this->ensureKeyDirectoryExists();

        /*
         * Existing key found.
         *
         * Validate it instead of generating a new one.
         */
        if (is_file($this->keyFile)) {
            $this->validateStoredKey();

            return true;
        }

        /*
         * Generate cryptographically secure random bytes.
         */
        try {
            $key = random_bytes(self::KEY_LENGTH_BYTES);
        } catch (Throwable $exception) {
            throw new RuntimeException(
                'Unable to generate SecureLog encryption key.',
                0,
                $exception
            );
        }

        /*
         * Store the binary key using Base64 encoding.
         *
         * IMPORTANT:
         * Base64 is NOT encryption.
         * It is only used to safely store binary key material.
         */
        $encodedKey = base64_encode($key);

        $written = file_put_contents(
            $this->keyFile,
            $encodedKey,
            LOCK_EX
        );

        if ($written === false) {
            throw new RuntimeException(
                'Unable to store SecureLog master encryption key.'
            );
        }

        /*
         * Best-effort restrictive permission.
         *
         * Useful on Linux/Unix deployments.
         * Windows ultimately uses Windows ACL permissions.
         */
        @chmod($this->keyFile, 0600);

        /*
         * Verify the newly created key.
         */
        $this->validateStoredKey();

        return true;
    }


    /* ============================================================
       KEY STATUS
       ============================================================ */

    /**
     * Determine whether a valid master key exists.
     *
     * The actual key is NEVER exposed.
     */
    public function keyExists(): bool
    {
        if (!is_file($this->keyFile)) {
            return false;
        }

        try {
            $this->validateStoredKey();

            return true;
        } catch (Throwable $exception) {
            return false;
        }
    }


    /**
     * Safe diagnostic information.
     *
     * This method NEVER returns key material.
     */
    public function getKeyStatus(): array
    {
        return [
            'initialized' => $this->keyExists(),
            'algorithm'   => strtoupper(self::CIPHER),
            'key_bits'    => 256,
            'format'      => self::VAULT_FORMAT,
            'version'     => self::VAULT_VERSION,
        ];
    }


    /* ============================================================
       AES-256-GCM ENCRYPTION
       ============================================================ */

    /**
     * Encrypt plaintext audit-log data.
     *
     * Returns an authenticated SecureLog Vault envelope.
     */
    public function encrypt(string $plaintext): array
    {
        if ($plaintext === '') {
            throw new InvalidArgumentException(
                'Cannot seal an empty audit log.'
            );
        }

        /*
         * Ensure OpenSSL supports AES-256-GCM.
         */
        $availableCiphers = openssl_get_cipher_methods();

        if (!in_array(self::CIPHER, $availableCiphers, true)) {
            throw new RuntimeException(
                'AES-256-GCM is not supported by this PHP/OpenSSL installation.'
            );
        }

        /*
         * Load the secret 256-bit master key.
         */
        $key = $this->loadKey();

        /*
         * Determine correct IV length for AES-GCM.
         *
         * Usually 12 bytes for AES-GCM.
         */
        $ivLength = openssl_cipher_iv_length(self::CIPHER);

        if ($ivLength === false || $ivLength <= 0) {
            throw new RuntimeException(
                'Unable to determine AES-GCM IV length.'
            );
        }

        /*
         * IMPORTANT:
         * Every encryption operation receives a new random IV.
         *
         * Never reuse an IV with the same AES-GCM key.
         */
        try {
            $iv = random_bytes($ivLength);
        } catch (Throwable $exception) {
            throw new RuntimeException(
                'Unable to generate AES-GCM initialization vector.',
                0,
                $exception
            );
        }

        /*
         * Unique archive identifier.
         */
        try {
            $archiveId =
                'SLV-'
                . strtoupper(bin2hex(random_bytes(8)));
        } catch (Throwable $exception) {
            throw new RuntimeException(
                'Unable to generate SecureLog archive identifier.',
                0,
                $exception
            );
        }

        /*
         * Archive creation timestamp.
         */
        $createdAt = (
            new DateTimeImmutable(
                'now',
                new DateTimeZone('Asia/Kuala_Lumpur')
            )
        )->format(DATE_ATOM);

        /*
         * These fields form authenticated metadata.
         *
         * AES-GCM Additional Authenticated Data (AAD) means these
         * values are not encrypted, but modification of them will
         * cause authentication/decryption to fail.
         */
        $aad = $this->buildAAD(
            self::VAULT_FORMAT,
            self::VAULT_VERSION,
            self::CIPHER,
            $archiveId,
            $createdAt
        );

        /*
         * OpenSSL writes the authentication tag into $tag.
         */
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::TAG_LENGTH_BYTES
        );

        if ($ciphertext === false) {
            throw new RuntimeException(
                'SecureLog audit log encryption failed.'
            );
        }

        if (strlen($tag) !== self::TAG_LENGTH_BYTES) {
            throw new RuntimeException(
                'Invalid AES-GCM authentication tag generated.'
            );
        }

        /*
         * Binary cryptographic values are Base64 encoded so that
         * the final .slog archive can safely use JSON.
         *
         * Again:
         * Base64 is encoding, NOT encryption.
         */
        return [
            'format'     => self::VAULT_FORMAT,
            'version'    => self::VAULT_VERSION,
            'algorithm'  => strtoupper(self::CIPHER),
            'archive_id' => $archiveId,
            'created_at' => $createdAt,

            'iv'         => base64_encode($iv),
            'tag'        => base64_encode($tag),
            'ciphertext' => base64_encode($ciphertext),
        ];
    }


    /* ============================================================
       AES-256-GCM DECRYPTION + VERIFICATION
       ============================================================ */

    /**
     * Verify and decrypt a SecureLog Vault envelope.
     *
     * AES-GCM performs authentication verification before
     * returning the plaintext.
     *
     * If ciphertext, tag, IV or authenticated metadata has been
     * modified, decryption fails.
     */
    public function decrypt(array $archive): string
    {
        $this->validateArchiveStructure($archive);

        /*
         * Normalize algorithm representation.
         */
        $algorithm = strtolower(
            (string) $archive['algorithm']
        );

        /*
         * Only the expected SecureLog format is accepted.
         */
        if ($archive['format'] !== self::VAULT_FORMAT) {
            throw new RuntimeException(
                'Unsupported SecureLog Vault archive format.'
            );
        }

        if ((int) $archive['version'] !== self::VAULT_VERSION) {
            throw new RuntimeException(
                'Unsupported SecureLog Vault archive version.'
            );
        }

        if ($algorithm !== self::CIPHER) {
            throw new RuntimeException(
                'Unsupported SecureLog Vault encryption algorithm.'
            );
        }

        /*
         * Decode cryptographic components.
         *
         * Strict Base64 decoding prevents malformed data
         * from being silently accepted.
         */
        $iv = base64_decode(
            (string) $archive['iv'],
            true
        );

        $tag = base64_decode(
            (string) $archive['tag'],
            true
        );

        $ciphertext = base64_decode(
            (string) $archive['ciphertext'],
            true
        );

        if (
            $iv === false
            || $tag === false
            || $ciphertext === false
        ) {
            throw new RuntimeException(
                'SecureLog archive contains invalid encoded cryptographic data.'
            );
        }

        /*
         * Validate IV length.
         */
        $expectedIvLength =
            openssl_cipher_iv_length(self::CIPHER);

        if (
            $expectedIvLength === false
            || strlen($iv) !== $expectedIvLength
        ) {
            throw new RuntimeException(
                'SecureLog archive contains an invalid AES-GCM IV.'
            );
        }

        /*
         * Validate authentication tag length.
         */
        if (strlen($tag) !== self::TAG_LENGTH_BYTES) {
            throw new RuntimeException(
                'SecureLog archive contains an invalid authentication tag.'
            );
        }

        /*
         * Reconstruct exactly the same authenticated metadata
         * used during encryption.
         */
        $aad = $this->buildAAD(
            (string) $archive['format'],
            (int) $archive['version'],
            $algorithm,
            (string) $archive['archive_id'],
            (string) $archive['created_at']
        );

        /*
         * Load the secret key.
         */
        $key = $this->loadKey();

        /*
         * AES-GCM verification happens here.
         *
         * If authentication fails, OpenSSL returns false.
         */
        $plaintext = openssl_decrypt(
            $ciphertext,
            self::CIPHER,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad
        );

        if ($plaintext === false) {
            throw new RuntimeException(
                'SecureLog Vault integrity verification failed. '
                . 'The archive may have been modified, corrupted, '
                . 'or encrypted using a different key.'
            );
        }

        return $plaintext;
    }


    /* ============================================================
       ARCHIVE VERIFICATION
       ============================================================ */

    /**
     * Verify whether an encrypted archive is authentic.
     *
     * Plaintext is not returned to the caller.
     */
    public function verify(array $archive): bool
    {
        try {
            $this->decrypt($archive);

            return true;
        } catch (Throwable $exception) {
            return false;
        }
    }


    /* ============================================================
       PRIVATE KEY MANAGEMENT
       ============================================================ */

    /**
     * Load the raw 256-bit master key.
     *
     * PRIVATE on purpose:
     * Other application modules should never obtain the raw key.
     */
    private function loadKey(): string
    {
        if (!is_file($this->keyFile)) {
            throw new RuntimeException(
                'SecureLog Vault master key has not been initialized.'
            );
        }

        $encodedKey = file_get_contents(
            $this->keyFile
        );

        if ($encodedKey === false) {
            throw new RuntimeException(
                'Unable to read SecureLog Vault master key.'
            );
        }

        $encodedKey = trim($encodedKey);

        $key = base64_decode(
            $encodedKey,
            true
        );

        if ($key === false) {
            throw new RuntimeException(
                'SecureLog Vault master key contains invalid Base64 data.'
            );
        }

        if (strlen($key) !== self::KEY_LENGTH_BYTES) {
            throw new RuntimeException(
                'SecureLog Vault master key must be exactly 256 bits.'
            );
        }

        return $key;
    }


    /**
     * Validate stored key without exposing it.
     */
    private function validateStoredKey(): void
    {
        $this->loadKey();
    }


    /**
     * Ensure SecureLog key directory exists.
     */
    private function ensureKeyDirectoryExists(): void
    {
        if (is_dir($this->keyDirectory)) {
            return;
        }

        $created = mkdir(
            $this->keyDirectory,
            0700,
            true
        );

        if (!$created && !is_dir($this->keyDirectory)) {
            throw new RuntimeException(
                'Unable to create SecureLog Vault key directory.'
            );
        }
    }


    /* ============================================================
       AUTHENTICATED METADATA
       ============================================================ */

    /**
     * Build deterministic Additional Authenticated Data (AAD).
     *
     * AAD is NOT encrypted.
     *
     * However, AES-GCM authenticates it. If an attacker changes
     * any of these values, verification will fail.
     */
    private function buildAAD(
        string $format,
        int $version,
        string $algorithm,
        string $archiveId,
        string $createdAt
    ): string {
        return implode(
            '|',
            [
                $format,
                (string) $version,
                strtolower($algorithm),
                $archiveId,
                $createdAt,
            ]
        );
    }


    /* ============================================================
       ARCHIVE VALIDATION
       ============================================================ */

    /**
     * Validate that all required archive fields exist.
     */
    private function validateArchiveStructure(array $archive): void
    {
        $requiredFields = [
            'format',
            'version',
            'algorithm',
            'archive_id',
            'created_at',
            'iv',
            'tag',
            'ciphertext',
        ];

        foreach ($requiredFields as $field) {
            if (
                !array_key_exists($field, $archive)
                || $archive[$field] === ''
                || $archive[$field] === null
            ) {
                throw new RuntimeException(
                    'SecureLog archive is missing required field: '
                    . $field
                );
            }
        }
    }
}