<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

    <h1>Hello, <?= htmlspecialchars($user['firstname'] ?? '') ?> <?= htmlspecialchars($user['lastname'] ?? '') ?>!</h1>
    <p>Email: <?= htmlspecialchars($user['email'] ?? '') ?></p>

<form action="/user/change-password" method="POST">
    <label for="old_password">Old Password</label>
    <input type="password" name="old_password" required>

    <label for="new_password">New Password</label>
    <input type="password" name="new_password" required>

    <label for="confirm_password">Confirm New Password</label>
    <input type="password" name="confirm_password" required>

    <input type="submit" value="Change Password">
</form>

<?php if (!empty($messages)): ?>
    <hr/>
    <?php foreach ($messages as $message): ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>


<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>