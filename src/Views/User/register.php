<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<div class="login-header">
    <h2>S'incrire</h2>
</div>

<form action="/register" method="post" class ="login-form">
    <div>
        <label>
            Email:
            <input type="email" name="email" required <?php if (isset($userForm['email'])): ?>value='<?= htmlspecialchars($userForm['email']) ?>'<?php endif; ?> />
        </label>
    </div>
    <div>
        <label>
            Password:
            <input type="password" name="password" required />
        </label>
    </div>
    <div>
        <label>
            Password confirmation:
            <input type="password" name="password_confirm" required />
        </label>
    </div>
    <div>
        <label>
            Lastname:
            <input type="text" name="lastname" required <?php if (isset($userForm['lastname'])): ?>value='<?= htmlspecialchars($userForm['lastname']) ?>'<?php endif; ?> />
        </label>
    </div>
    <div>
        <label>
            Firstname:
            <input type="text" name="firstname" required <?php if (isset($userForm['firstname'])): ?>value='<?= htmlspecialchars($userForm['firstname']) ?>'<?php endif; ?> />
        </label>
    </div>
    <div>
        <button type="submit">Register</button>
    </div>
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
