<?php
/**
 * SecureLog Developer Sidebar
 * File: Sidebar/sidebaruser.php
 */

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
|--------------------------------------------------------------------------
| Base URL
|--------------------------------------------------------------------------
| Using a fixed base URL prevents broken links when the sidebar is included
| from different folders.
*/
$baseUrl = '/FinalYearProject';

/* Current page and folder for active-menu detection */
$currentPage = basename($_SERVER['PHP_SELF']);
$currentDirectory = basename(dirname($_SERVER['PHP_SELF']));

/* Current logged-in user */
$developerName = $_SESSION['fullname']
    ?? $_SESSION['username']
    ?? 'Developer';

/**
 * Return active class when the current page matches.
 */
function developerSidebarActive(
    array $pages,
    string $currentPage
): string {
    return in_array(
        $currentPage,
        $pages,
        true
    ) ? 'active' : '';
}
?>

<link
    rel="stylesheet"
    href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
>

<link
    rel="stylesheet"
    href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap"
>

<style>
    :root {
        --developer-sidebar-width: 260px;
        --developer-sidebar-bg: #07172a;
        --developer-sidebar-border: #1b2e45;

        --developer-blue: #1168f4;
        --developer-blue-light: #3182ff;
        --developer-red: #ff4c5f;

        --developer-text: #ffffff;
        --developer-muted: #9aa9bc;
    }

    * {
        box-sizing: border-box;
    }

    /* =========================================================
       SIDEBAR
       ========================================================= */

    .developer-sidebar {
        position: fixed;
        top: 0;
        left: 0;
        z-index: 1000;

        width: var(--developer-sidebar-width);
        height: 100vh;

        display: flex;
        flex-direction: column;

        padding: 36px 14px 24px;

        color: var(--developer-text);
        background:
            linear-gradient(
                180deg,
                #0b1a30 0%,
                #071526 100%
            );

        border-right: 1px solid var(--developer-sidebar-border);

        font-family:
            "Inter",
            "Segoe UI",
            sans-serif;
    }

    /* =========================================================
       BRAND
       ========================================================= */

    .developer-sidebar__brand {
        margin: 0 14px 42px;

        color: var(--developer-blue-light);

        font-size: 25px;
        font-weight: 800;
        letter-spacing: 0.4px;
        text-transform: uppercase;
    }

    /* =========================================================
       NAVIGATION
       ========================================================= */

    .developer-sidebar__navigation {
        display: flex;
        flex-direction: column;
        gap: 7px;
    }

    .developer-sidebar__link {
        min-height: 56px;
        padding: 0 17px;

        display: flex;
        align-items: center;
        gap: 15px;

        color: #f3f6fa;
        background: transparent;

        border: 1px solid transparent;
        border-radius: 8px;

        text-decoration: none;

        font-size: 16px;
        font-weight: 600;

        transition:
            color 0.2s ease,
            background-color 0.2s ease,
            border-color 0.2s ease,
            transform 0.2s ease;
    }

    .developer-sidebar__link i {
        width: 27px;

        color: #f3f6fa;

        font-size: 23px;
        text-align: center;

        transition: color 0.2s ease;
    }

    .developer-sidebar__link:hover {
        color: #ffffff;
        background: rgba(49, 130, 255, 0.12);
        border-color: rgba(49, 130, 255, 0.18);

        transform: translateX(2px);
    }

    .developer-sidebar__link:hover i {
        color: var(--developer-blue-light);
    }

    /* Active menu */
    .developer-sidebar__link.active {
        color: #ffffff;
        background:
            linear-gradient(
                135deg,
                #1264e8,
                #0858dd
            );

        border-color: rgba(49, 130, 255, 0.45);

        box-shadow:
            0 8px 22px rgba(17, 104, 244, 0.24);
    }

    .developer-sidebar__link.active i {
        color: #ffffff;
    }

    /* =========================================================
       BOTTOM AREA
       ========================================================= */

    .developer-sidebar__bottom {
        margin-top: auto;
        padding-top: 22px;

        border-top: 1px solid var(--developer-sidebar-border);
    }

    .developer-sidebar__account {
        margin-bottom: 15px;
        padding: 10px 14px;

        display: flex;
        align-items: center;
        gap: 12px;

        color: var(--developer-muted);

        font-size: 12px;
    }

    .developer-sidebar__account-icon {
        width: 39px;
        height: 39px;

        display: flex;
        align-items: center;
        justify-content: center;
        flex-shrink: 0;

        color: var(--developer-blue-light);
        background: rgba(49, 130, 255, 0.12);

        border: 1px solid rgba(49, 130, 255, 0.25);
        border-radius: 50%;

        font-size: 17px;
    }

    .developer-sidebar__account-details {
        min-width: 0;
    }

    .developer-sidebar__account-label {
        margin-bottom: 4px;

        color: var(--developer-muted);

        font-size: 11px;
    }

    .developer-sidebar__account-name {
        max-width: 150px;

        overflow: hidden;

        color: #ffffff;

        font-size: 13px;
        font-weight: 700;
        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .developer-sidebar__logout {
        min-height: 51px;
        padding: 0 17px;

        display: flex;
        align-items: center;
        gap: 15px;

        color: var(--developer-red);
        background: transparent;

        border: 1px solid transparent;
        border-radius: 8px;

        text-decoration: none;

        font-size: 15px;
        font-weight: 700;

        transition:
            color 0.2s ease,
            background-color 0.2s ease,
            border-color 0.2s ease;
    }

    .developer-sidebar__logout i {
        width: 27px;

        font-size: 22px;
        text-align: center;
    }

    .developer-sidebar__logout:hover {
        color: #ffffff;
        background: rgba(255, 76, 95, 0.13);
        border-color: rgba(255, 76, 95, 0.25);
    }

    /* =========================================================
       PAGE CONTENT BESIDE SIDEBAR
       ========================================================= */

    .developer-page-content {
        min-height: 100vh;
        margin-left: var(--developer-sidebar-width);
    }

    /*
     * Compatibility with pages that use admin-page-content
     * or another existing page-content class.
     */
    .admin-page-content {
        margin-left: var(--developer-sidebar-width);
    }

    /* =========================================================
       RESPONSIVE
       ========================================================= */

    @media (max-width: 800px) {
        .developer-sidebar {
            width: 220px;
        }

        .developer-page-content,
        .admin-page-content {
            margin-left: 220px;
        }

        .developer-sidebar__link {
            font-size: 14px;
        }
    }
</style>

<aside class="developer-sidebar">

    <!-- Brand -->
    <div class="developer-sidebar__brand">
        SAST Tool
    </div>

    <!-- Main navigation -->
    <nav class="developer-sidebar__navigation">

        <!-- Dashboard -->
        <a
            href="<?= $baseUrl ?>/Dashboard/dashboard_Developer.php"
            class="developer-sidebar__link <?= developerSidebarActive(
                ['dashboard_Developer.php'],
                $currentPage
            ); ?>"
        >
            <i class="fa-solid fa-border-all"></i>
            <span>Dashboard</span>
        </a>

        <!-- New Scan -->
        <a
            href="<?= $baseUrl ?>/Engine_Process/index.php"
            class="developer-sidebar__link <?= developerSidebarActive(
                ['index.php'],
                $currentPage
            ) && $currentDirectory === 'Engine_Process'
                ? 'active'
                : ''; ?>"
        >
            <i class="fa-solid fa-magnifying-glass"></i>
            <span>New Scan</span>
        </a>

        <!-- History -->
        <a
            href="<?= $baseUrl ?>/History/index.php"
            class="developer-sidebar__link <?= developerSidebarActive(
                ['index.php'],
                $currentPage
            ) && $currentDirectory === 'History'
                ? 'active'
                : ''; ?>"
        >
            <i class="fa-solid fa-clock-rotate-left"></i>
            <span>History</span>
        </a>

        <!-- Profile -->
        <a
            href="<?= $baseUrl ?>/ProfileDeveloper/profile.php"
            class="developer-sidebar__link <?= developerSidebarActive(
                ['profile.php'],
                $currentPage
            ); ?>"
        >
            <i class="fa-regular fa-user"></i>
            <span>Profile</span>
        </a>

    </nav>

    <!-- Bottom account and logout -->
    <div class="developer-sidebar__bottom">

        <div class="developer-sidebar__account">

            <div class="developer-sidebar__account-icon">
                <i class="fa-solid fa-user-code"></i>
            </div>

            <div class="developer-sidebar__account-details">

                <div class="developer-sidebar__account-label">
                    Signed in as
                </div>

                <div class="developer-sidebar__account-name">
                    <?= htmlspecialchars(
                        $developerName,
                        ENT_QUOTES,
                        'UTF-8'
                    ); ?>
                </div>

            </div>

        </div>

        <a
            href="<?= $baseUrl ?>/Registration/Logout.php"
            class="developer-sidebar__logout"
            onclick="return confirm('Are you sure you want to log out?');"
        >
            <i class="fa-solid fa-right-from-bracket"></i>
            <span>Logout</span>
        </a>

    </div>

</aside>