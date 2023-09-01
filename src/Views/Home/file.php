<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<h2>Download file: <?= htmlspecialchars($file['filename'] ?? '') ?></h2>

<p>Description: <?= htmlspecialchars($file['description'] ?? '') ?></p>
<p>Size: <?= htmlspecialchars($file['size'] ?? '') ?></p>
<p>Download count: <?= htmlspecialchars($file['downloadCount'] ?? '') ?></p>
<p>Created at: <?= htmlspecialchars($file['createdAt'] ?? '') ?></p>

<form action="/dl/<?= htmlspecialchars($file['token'] ?? '', ENT_QUOTES) ?>" method="post">
    <?php if ($file['hasPassword'] ?? false): ?>
        <div>
            <label>
                <input type="password" name="password" placeholder="Password" required/>
            </label>
        </div>
    <?php endif; ?>
    <input type="hidden" name="csrf" value="<?= $csrf ?? '' ?>" />
    <button type="submit">Download</button>
</form>

<?php if (!empty($messages)): ?>
    <hr/>
    <p>Errors:</p>
    <?php foreach ($messages as $message): ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>
