<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

    <h1>Bonjour, <?= htmlspecialchars($user['firstname'] ?? '') ?> <?= htmlspecialchars($user['lastname'] ?? '') ?>!</h1>
    <p>Email: <?= htmlspecialchars($user['email'] ?? '') ?></p>

<form action="/user/change-password" method="POST">
    <label for="old_password">Ancien mot de passe</label>
    <input type="password" name="old_password" required>

    <label for="new_password">Nouveau mot de passe</label>
    <input type="password" name="new_password" required>

    <label for="confirm_password">Confirmer nouveau mot de passe</label>
    <input type="password" name="confirm_password" required>

    <input type="submit" value="Changer mot de passe">
</form>

<?php if (!empty($messages)): ?>
    <hr/>
    <?php foreach ($messages as $message): ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>


<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>