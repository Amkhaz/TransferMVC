<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<div class="login-header">
    <h2>S'incrire</h2>
</div>

<form action="/register" method="post" class ="login-form">
    <label>
        Nom:
        <input type="text" name="lastname" required <?php if (isset($userForm['lastname'])): ?>value='<?= htmlspecialchars($userForm['lastname']) ?>'<?php endif; ?> />
    </label>
</div>
<div>
    <label>
        Prénom:
        <input type="text" name="firstname" required <?php if (isset($userForm['firstname'])): ?>value='<?= htmlspecialchars($userForm['firstname']) ?>'<?php endif; ?> />
    </label>
</div>
<div>
    <label>
        Email:
        <input type="email" name="email" required <?php if (isset($userForm['email'])): ?>value='<?= htmlspecialchars($userForm['email']) ?>'<?php endif; ?> />
        </label>
    </div>
    <div>
        <label>
            Mot de passe:
            <input type="password" name="password" required />
        </label>
    </div>
    <div>
        <label>
            Confirmer mot de passe:
            <input type="password" name="password_confirm" required />
        </label>
    </div>
    <div>
        <button type="submit">S'inscrire</button>
    </div>
    <div>
</form>

<div>
    <?php if (isset($error)): ?>
        <div>
            <?php foreach ($error as $e): ?>
                <div><?= htmlspecialchars($e) ?></div>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>

    <?php if (isset($success)): ?>
        <div>
            <?= htmlspecialchars($success) ?>
        </div>
    <?php endif; ?>
</div>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>
