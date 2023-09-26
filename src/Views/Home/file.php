<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<h2>Nom du fichier: <?= htmlspecialchars($file['filename'] ?? '') ?></h2>

<table class="file-table">
    <thead>
        <tr>
            <th>Description:</th>
            <th>Taille: </th>
            <th>Nombre de téléchargements:</th>
            <th>Date de création:</th>
        </tr>
        <tr>
            <td><?= htmlspecialchars($file['description'] ?? '') ?></td>
            <td><?= htmlspecialchars($file['size'] ?? '') ?></td>
            <td><?= htmlspecialchars($file['downloadCount'] ?? '') ?></td>
            <td><?= htmlspecialchars($file['createdAt'] ?? '') ?></td>
        </tr>
    </thead>
</table>

<form action="/dl/<?= htmlspecialchars($file['token'] ?? '', ENT_QUOTES) ?>" method="post">
    <?php if ($file['hasPassword'] ?? false) : ?>
        <div>
            <label>
                <input type="password" name="password" placeholder="Password" required />
            </label>
        </div>
    <?php endif; ?>
    <input type="hidden" name="csrf" value="<?= $csrf ?? '' ?>" />
    <button type="submit">Télécharger</button>
</form>

<?php if (!empty($messages)) : ?>
    <hr />
    <p>Errors:</p>
    <?php foreach ($messages as $message) : ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>

<?php if (!empty($comments)) : ?>
    <hr />
    <p>Commentaires:</p>
    <?php foreach ($comments as $comment) : ?>
        <p>From <?= htmlspecialchars($comment['firstname'] . ' ' . $comment['lastname']) ?></p>
        <div><?= htmlspecialchars($comment['content']) ?></div>
    <?php endforeach; ?>
<?php endif; ?>

<h3>Ajouter un commentaire:</h3>

<?php if ($isConnected ?? false) : ?>
    <form action="/comment/add/<?= htmlspecialchars($file['token'] ?? '', ENT_QUOTES) ?>" method="post">
        <div>
            <label>
                <textarea name="content" placeholder="Content" cols="50" rows="10" required></textarea>
            </label>
        </div>
        <input type="hidden" name="csrf" value="<?= $csrf ?? '' ?>" />
        <button type="submit">Ajouter</button>
    </form>
<?php else : ?>
    <p>Vous devez être connecté pour ajouter un commentaire</p>
<?php endif; ?>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>