<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<div class="login-header">
    <h2>Connexion</h2>
</div>

<form action="/login_check" method="post" class="login-form">
    <div>
        <label>
            Email:
            <input type="email" name="email" required <?php if (isset($email)): ?>value='<?= htmlspecialchars($email) ?>'<?php endif; ?> />
        </label>
    </div>
    <div>
        <label>
            Password:
            <input type="password" name="password" required />
        </label>
    </div>
    <div>
        <button type="submit">Se connecter</button>
    </div>
    <input type="hidden" name="csrf" value="<?= $csrf ?? '' ?>" />
</form>

<div>
    <?php if (isset($error)): ?>
        <div>
            <?= htmlspecialchars($error) ?>
        </div>
    <?php endif; ?>
</div>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>
