```php
<?php
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

/*
|--------------------------------------------------------------------------
| Project URL
|--------------------------------------------------------------------------
| Change this if your XAMPP project folder uses another name.
*/
$baseUrl = '/FinalYearProject';

/*
|--------------------------------------------------------------------------
| SecureLog image
|--------------------------------------------------------------------------
| Location: FinalYearProject/Asset/securelog.png
*/
$logoUrl = $baseUrl . '/Asset/securelog.png';

$currentPage = basename($_SERVER['PHP_SELF']);

$adminName = $_SESSION['fullname']
    ?? $_SESSION['username']
    ?? 'Administrator';

if (!function_exists('sidebarActive')) {
    function sidebarActive(array $pages, string $currentPage): string
    {
        return in_array($currentPage, $pages, true)
            ? 'active'
            : '';
    }
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
        --admin-sidebar-width: 250px;

        --sidebar-bg: #03111f;
        --sidebar-border: rgba(148, 163, 184, 0.15);

        --sidebar-text: #f8fafc;
        --sidebar-muted: #8796aa;

        --sidebar-orange: #ff6500;
        --sidebar-red: #ff3f46;
    }

    * {
        box-sizing: border-box;
    }

    /* =========================================================
       MAIN SIDEBAR
       ========================================================= */

    .admin-sidebar {
        position: fixed;
        top: 0;
        left: 0;
        z-index: 1000;

        width: var(--admin-sidebar-width);
        min-width: var(--admin-sidebar-width);
        height: 100vh;

        display: flex;
        flex-direction: column;

        background:
            radial-gradient(
                circle at top left,
                rgba(255, 101, 0, 0.05),
                transparent 30%
            ),
            var(--sidebar-bg);

        border-right: 1px solid var(--sidebar-border);

        color: var(--sidebar-text);
        font-family: "Inter", "Segoe UI", sans-serif;

        overflow-x: hidden;
        overflow-y: auto;
    }

    /* =========================================================
       LARGE SECURELOG LOGO
       ========================================================= */

    .admin-sidebar__brand {
        width: 100%;
        min-height: 118px;
        padding: 15px 20px;

        display: flex;
        align-items: center;
        justify-content: center;

        text-decoration: none;
        overflow: hidden;
    }

    /*
     * securelog.png has large empty space around the logo.
     * The background settings below zoom and crop that space.
     */
    .admin-sidebar__brand-image {
        width: 210px;
        height: 78px;

        background-image: var(--securelog-image);
        background-repeat: no-repeat;

        background-size: 310px auto;
        background-position: center -174px;

        flex-shrink: 0;
    }

    /* =========================================================
       NAVIGATION
       ========================================================= */

    .admin-sidebar__navigation {
        flex: 1;
        padding: 0 14px 25px;
    }

    .admin-sidebar__section {
        margin-bottom: 30px;
    }

    .admin-sidebar__section-title {
        margin: 0 15px 12px;

        color: var(--sidebar-muted);

        font-size: 12px;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.8px;
    }

    .admin-sidebar__link {
        position: relative;

        width: 100%;
        min-height: 55px;

        margin-bottom: 4px;
        padding: 0 17px;

        display: flex;
        align-items: center;
        gap: 18px;

        color: #f0f4f8;
        text-decoration: none;

        border-radius: 7px;

        font-size: 15px;
        font-weight: 500;

        transition:
            background-color 0.2s ease,
            color 0.2s ease,
            transform 0.2s ease;
    }

    .admin-sidebar__link i {
        width: 26px;

        color: #f8fafc;

        font-size: 22px;
        text-align: center;

        transition: color 0.2s ease;
    }

    .admin-sidebar__link:hover {
        color: #ffffff;
        background: rgba(255, 101, 0, 0.09);

        transform: translateX(2px);
    }

    .admin-sidebar__link:hover i {
        color: var(--sidebar-orange);
    }

    .admin-sidebar__link.active {
        color: #ffffff;

        background:
            linear-gradient(
                90deg,
                rgba(126, 45, 0, 0.95),
                rgba(92, 32, 0, 0.75)
            );

        box-shadow:
            inset 3px 0 0 var(--sidebar-orange),
            0 7px 18px rgba(0, 0, 0, 0.18);
    }

    .admin-sidebar__link.active i {
        color: var(--sidebar-orange);
    }

    /* =========================================================
       EXPORT ENCRYPTED LOG
       ========================================================= */

    .admin-sidebar__export {
        width: calc(100% - 18px);
        min-height: 54px;

        margin: 0 9px;
        padding: 0 16px;

        display: flex;
        align-items: center;
        gap: 14px;

        color: var(--sidebar-orange);
        background: transparent;

        border: 1px solid var(--sidebar-orange);
        border-radius: 7px;

        text-decoration: none;

        font-size: 14px;
        font-weight: 700;
        line-height: 1.25;

        transition:
            background-color 0.2s ease,
            color 0.2s ease,
            box-shadow 0.2s ease;
    }

    .admin-sidebar__export i {
        width: 20px;

        font-size: 19px;
        text-align: center;
        flex-shrink: 0;
    }

    .admin-sidebar__export:hover {
        color: #ffffff;
        background: var(--sidebar-orange);

        box-shadow:
            0 0 18px rgba(255, 101, 0, 0.25);
    }

    /* =========================================================
       SIDEBAR FOOTER
       ========================================================= */

    .admin-sidebar__footer {
        padding: 20px 15px 25px;

        border-top: 1px solid var(--sidebar-border);
    }

    /* =========================================================
       SIGNED-IN PROFILE
       ========================================================= */

    .admin-sidebar__profile {
        width: 100%;
        padding: 0 8px 20px;

        display: grid;
        grid-template-columns: 48px minmax(0, 1fr) 16px;
        align-items: center;
        column-gap: 12px;
    }

    /*
     * Crops only the shield from securelog.png.
     */
    .admin-sidebar__profile-logo {
        width: 48px;
        height: 52px;

        background-image: var(--securelog-image);
        background-repeat: no-repeat;

        background-size: 270px auto;
        background-position: -43px -158px;

        flex-shrink: 0;
    }

    .admin-sidebar__profile-details {
        min-width: 0;
    }

    .admin-sidebar__profile-label {
        margin-bottom: 4px;

        color: var(--sidebar-muted);

        font-size: 12px;
        font-weight: 400;
    }

    .admin-sidebar__profile-name {
        width: 100%;
        max-width: 125px;

        overflow: hidden;

        color: #ffffff;

        font-size: 14px;
        font-weight: 700;

        text-overflow: ellipsis;
        white-space: nowrap;
    }

    .admin-sidebar__profile-arrow {
        color: #60a5fa;

        font-size: 12px;
        text-align: center;
    }

    /* =========================================================
       LOGOUT
       ========================================================= */

    .admin-sidebar__logout {
        width: 100%;
        min-height: 45px;

        padding: 0 17px;

        display: flex;
        align-items: center;
        gap: 17px;

        color: var(--sidebar-red);
        text-decoration: none;

        border-radius: 6px;

        font-size: 14px;
        font-weight: 700;

        transition:
            background-color 0.2s ease,
            color 0.2s ease;
    }

    .admin-sidebar__logout i {
        width: 25px;

        font-size: 22px;
        text-align: center;
    }

    .admin-sidebar__logout:hover {
        color: #ffffff;
        background: rgba(255, 63, 70, 0.12);
    }

    /* =========================================================
       SCROLLBAR
       ========================================================= */

    .admin-sidebar::-webkit-scrollbar {
        width: 5px;
    }

    .admin-sidebar::-webkit-scrollbar-track {
        background: transparent;
    }

    .admin-sidebar::-webkit-scrollbar-thumb {
        background: rgba(148, 163, 184, 0.18);
        border-radius: 10px;
    }

    .admin-sidebar::-webkit-scrollbar-thumb:hover {
        background: rgba(148, 163, 184, 0.3);
    }

    /* =========================================================
       PAGE CONTENT
       ========================================================= */

    .admin-page-content {
        margin-left: var(--admin-sidebar-width);
        min-height: 100vh;
    }

    /* =========================================================
       RESPONSIVE
       ========================================================= */

    @media (max-width: 800px) {
        .admin-sidebar {
            transform: translateX(-100%);
            transition: transform 0.3s ease;
        }

        .admin-sidebar.mobile-open {
            transform: translateX(0);
        }

        .admin-page-content {
            margin-left: 0;
        }
    }
</style>

<aside
    class="admin-sidebar"
    style="--securelog-image:
        url('<?= htmlspecialchars(
            $logoUrl,
            ENT_QUOTES,
            'UTF-8'
        ); ?>');"
>

    <!-- =====================================================
         LARGE SECURELOG LOGO
         ===================================================== -->

    <a
        href="<?= htmlspecialchars(
            $baseUrl . '/Dashboard/dashboard_Admin.php'
        ); ?>"
        class="admin-sidebar__brand"
        aria-label="SecureLog Admin Dashboard"
    >
        <div
            class="admin-sidebar__brand-image"
            role="img"
            aria-label="SecureLog"
        ></div>
    </a>

    <!-- =====================================================
         MENU
         ===================================================== -->

    <nav class="admin-sidebar__navigation">

        <!-- MONITOR -->
        <section class="admin-sidebar__section">

            <p class="admin-sidebar__section-title">
                Monitor
            </p>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl . '/Dashboard/dashboard_Admin.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    ['dashboard_Admin.php'],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-table-cells-large"></i>
                <span>Dashboard</span>
            </a>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl
                    . '/Dashboard/ActivityLog/activityLog.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    ['activityLog.php'],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-list"></i>
                <span>Activity Log</span>
            </a>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl . '/Dashboard/Scan/allScans.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    [
                        'allScans.php',
                        'scandetails.php'
                    ],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-magnifying-glass"></i>
                <span>All Scans</span>
            </a>

        </section>

        <!-- MANAGE -->
        <section class="admin-sidebar__section">

            <p class="admin-sidebar__section-title">
                Manage
            </p>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl
                    . '/ManageUser/addUser.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    ['addUser.php'],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-user-plus"></i>
                <span>Add User</span>
            </a>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl
                    . '/ManageUser/user.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    [
                        'user.php',
                        'editUser.php'
                    ],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-users"></i>
                <span>Manage Users</span>
            </a>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl . '/ScannerRule/ScannerRule.php'
                ); ?>"
                class="admin-sidebar__link <?= sidebarActive(
                    [
                        'ScannerRule.php',
                        'addRule.php',
                        'editRule.php'
                    ],
                    $currentPage
                ); ?>"
            >
                <i class="fa-solid fa-shield-halved"></i>
                <span>Scanner Rules</span>
            </a>

        </section>

        <!-- SYSTEM -->
        <section class="admin-sidebar__section">

            <p class="admin-sidebar__section-title">
                System
            </p>

            <a
                href="<?= htmlspecialchars(
                    $baseUrl
                    . '/Dashboard/dashboard_Admin.php?action=export_log'
                ); ?>"
                class="admin-sidebar__export"
            >
                <i class="fa-solid fa-download"></i>
                <span>Export Encrypted Log</span>
            </a>

        </section>

    </nav>

    <!-- =====================================================
         PROFILE AND LOGOUT
         ===================================================== -->

    <footer class="admin-sidebar__footer">

        <div class="admin-sidebar__profile">

            <!-- Shield cropped from securelog.png -->
            <div
                class="admin-sidebar__profile-logo"
                role="img"
                aria-label="SecureLog Shield"
            ></div>

            <div class="admin-sidebar__profile-details">

                <div class="admin-sidebar__profile-label">
                    Signed in as
                </div>

                <div class="admin-sidebar__profile-name">
                    <?= htmlspecialchars(
                        $adminName,
                        ENT_QUOTES,
                        'UTF-8'
                    ); ?>
                </div>

            </div>

            <i
                class="fa-solid fa-chevron-down
                       admin-sidebar__profile-arrow"
            ></i>

        </div>

        <a
            href="<?= htmlspecialchars(
                $baseUrl . '/Registration/logout.php'
            ); ?>"
            class="admin-sidebar__logout"
        >
            <i class="fa-solid fa-arrow-right-from-bracket"></i>
            <span>Logout</span>
        </a>

    </footer>

</aside>
```
