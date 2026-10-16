
<?php

function log_activity(
    string $event,
    ?int $userId,
    string $description
): void {

    $message = json_encode([
        'event' => $event,
        'user_id' => $userId,
        'description' => $description
    ]);

    if ($message !== false) {
        error_log($message);
    }
}
