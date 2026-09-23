<?php
/**
 * SecureLog - Scanner Rule Actions
 * File: ScannerRule/ruleAction.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/* ============================================================
   AUTHENTICATION
   ============================================================ */

require_once __DIR__ . '/../Dashboard/authCheck.php';

if (function_exists('require_role')) {
    require_role(['admin']);
}

/* ============================================================
   DATABASE
   ============================================================ */

require_once __DIR__ . '/../Engine_Process/connection.php';

if (!isset($conn) || !($conn instanceof mysqli)) {
    die('Database connection is not available.');
}

/* ============================================================
   ACTIVITY LOGGER
   ============================================================ */

$activityLoggerPath =
    __DIR__ . '/../Dashboard/ActivityLogger.php';

if (file_exists($activityLoggerPath)) {
    require_once $activityLoggerPath;
}

/* ============================================================
   CURRENT ADMIN
   ============================================================ */

$currentAdminId = (int) (
    $_SESSION['UserID']
    ?? $_SESSION['user_id']
    ?? 0
);

/* ============================================================
   HELPERS
   ============================================================ */

function redirectRuleAction(
    string $type,
    string $message
): void {
    header(
        'Location: scannerRule.php?'
        . http_build_query([
            'type' => $type,
            'message' => $message
        ])
    );

    exit();
}

/* ============================================================
   POST ONLY
   ============================================================ */

if (
    $_SERVER['REQUEST_METHOD']
    !== 'POST'
) {
    redirectRuleAction(
        'error',
        'Invalid request method.'
    );
}

/* ============================================================
   CSRF VALIDATION
   ============================================================ */

$submittedToken =
    $_POST['csrf_token']
    ?? '';

$sessionToken =
    $_SESSION['csrf_token']
    ?? '';

if (
    $sessionToken === ''
    || $submittedToken === ''
    || !hash_equals(
        $sessionToken,
        $submittedToken
    )
) {
    redirectRuleAction(
        'error',
        'Invalid request token. Please refresh the page and try again.'
    );
}

/* ============================================================
   INPUT
   ============================================================ */

$ruleId = (int) (
    $_POST['rule_id']
    ?? 0
);

$action = strtolower(
    trim(
        $_POST['action']
        ?? ''
    )
);

if ($ruleId <= 0) {
    redirectRuleAction(
        'error',
        'Invalid scanner rule.'
    );
}

$validActions = [
    'activate',
    'disable'
];

if (
    !in_array(
        $action,
        $validActions,
        true
    )
) {
    redirectRuleAction(
        'error',
        'Unsupported scanner rule action.'
    );
}

/* ============================================================
   LOAD RULE
   ============================================================ */

$ruleStatement =
    $conn->prepare(
        "
        SELECT
            RuleID,
            RuleCode,
            RuleName,
            Status,
            LastTestPassed,
            LastTestedAt

        FROM scanner_rules

        WHERE RuleID = ?

        LIMIT 1
        "
    );

if (!$ruleStatement) {
    redirectRuleAction(
        'error',
        'Unable to load scanner rule.'
    );
}

$ruleStatement->bind_param(
    'i',
    $ruleId
);

$ruleStatement->execute();

$ruleResult =
    $ruleStatement->get_result();

$rule =
    $ruleResult->fetch_assoc();

$ruleStatement->close();

if (!$rule) {
    redirectRuleAction(
        'error',
        'Scanner rule was not found.'
    );
}

/* ============================================================
   RULE VALUES
   ============================================================ */

$ruleCode =
    (string) $rule['RuleCode'];

$ruleName =
    (string) $rule['RuleName'];

$currentStatus =
    strtoupper(
        (string) $rule['Status']
    );

$lastTestPassed =
    (int) (
        $rule['LastTestPassed']
        ?? 0
    );

$lastTestedAt =
    $rule['LastTestedAt']
    ?? null;

/* ============================================================
   ACTIVATE RULE
   ============================================================ */

if ($action === 'activate') {

    /* --------------------------------------------------------
       ALREADY ACTIVE
       -------------------------------------------------------- */

    if ($currentStatus === 'ACTIVE') {

        redirectRuleAction(
            'warning',
            'Scanner rule is already active.'
        );
    }

    /* --------------------------------------------------------
       TEST REQUIRED
       -------------------------------------------------------- */

    if ($lastTestPassed !== 1) {

        redirectRuleAction(
            'error',
            'This scanner rule cannot be activated because it has not passed rule testing.'
        );
    }

    /* --------------------------------------------------------
       ACTIVATE
       -------------------------------------------------------- */

    $newStatus =
        'ACTIVE';

    $updateStatement =
        $conn->prepare(
            "
            UPDATE scanner_rules

            SET
                Status = ?,
                UpdatedAt = NOW()

            WHERE RuleID = ?

            LIMIT 1
            "
        );

    if (!$updateStatement) {

        redirectRuleAction(
            'error',
            'Unable to prepare rule activation.'
        );
    }

    $updateStatement->bind_param(
        'si',
        $newStatus,
        $ruleId
    );

    if (
        !$updateStatement->execute()
    ) {

        $updateStatement->close();

        redirectRuleAction(
            'error',
            'Failed to activate scanner rule.'
        );
    }

    $updateStatement->close();

    /* --------------------------------------------------------
    ACTIVITY LOG - RULE ACTIVATED
    -------------------------------------------------------- */

    if (
        $currentAdminId > 0
        && function_exists('log_activity')
    ) {

        log_activity(
            LOG_RULE_ACTIVATED,
            $currentAdminId,
            'Administrator activated a scanner rule.',
            [
                'module' => 'ScannerRule',
                'severity' => 'WARNING',
                'result' => 'SUCCESS',

                'target_type' => 'SCANNER_RULE',
                'target_id' => $ruleId,

                'metadata' => [
                    'rule_code' => $ruleCode,
                    'rule_name' => $ruleName,
                    'previous_status' => $currentStatus,
                    'new_status' => 'ACTIVE',
                    'last_test_passed' => true,
                    'last_tested_at' => $lastTestedAt
                ]
            ]
        );
    }

    redirectRuleAction(
        'success',
        "Scanner rule {$ruleCode} activated successfully."
    );
}
/* ============================================================
   DISABLE RULE
   ============================================================ */

if ($action === 'disable') {

    /* --------------------------------------------------------
       ALREADY DISABLED
       -------------------------------------------------------- */

    if ($currentStatus === 'DISABLED') {

        redirectRuleAction(
            'warning',
            'Scanner rule is already disabled.'
        );
    }


    /* --------------------------------------------------------
       DISABLE RULE
       -------------------------------------------------------- */

    $newStatus = 'DISABLED';

    $updateStatement =
        $conn->prepare(
            "
            UPDATE scanner_rules
            SET
                Status = ?,
                UpdatedAt = NOW()
            WHERE RuleID = ?
            LIMIT 1
            "
        );

    if (!$updateStatement) {

        redirectRuleAction(
            'error',
            'Unable to prepare rule disable action.'
        );
    }


    $updateStatement->bind_param(
        'si',
        $newStatus,
        $ruleId
    );


    if (!$updateStatement->execute()) {

        $updateStatement->close();

        redirectRuleAction(
            'error',
            'Failed to disable scanner rule.'
        );
    }


    $updateStatement->close();


    /* --------------------------------------------------------
       ACTIVITY LOG - RULE DISABLED
       -------------------------------------------------------- */

    if (
        $currentAdminId > 0
        && function_exists('log_activity')
    ) {

        log_activity(
            LOG_RULE_DISABLED,
            $currentAdminId,
            'Administrator disabled a scanner rule.',
            [
                'module' => 'ScannerRule',
                'severity' => 'WARNING',
                'result' => 'SUCCESS',

                'target_type' => 'SCANNER_RULE',
                'target_id' => $ruleId,

                'metadata' => [
                    'rule_code' =>
                        $ruleCode,

                    'rule_name' =>
                        $ruleName,

                    'previous_status' =>
                        $currentStatus,

                    'new_status' =>
                        $newStatus
                ]
            ]
        );
    }


    /* --------------------------------------------------------
       SUCCESS REDIRECT
       -------------------------------------------------------- */

    redirectRuleAction(
        'success',
        "Scanner rule {$ruleCode} disabled successfully."
    );

    exit();
}


/* ============================================================
   FALLBACK
   ============================================================ */

redirectRuleAction(
    'error',
    'Unable to process scanner rule action.'
);

/* ============================================================
   FALLBACK
   ============================================================ */

redirectRuleAction(
    'error',
    'Unable to process scanner rule action.'
);