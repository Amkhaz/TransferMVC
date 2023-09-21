<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<div class="title">
    <h2>Tableau de bord</h2>
</div>

<p>Bonjour <?= htmlspecialchars($name ?? '', ENT_QUOTES) ?>!</p>

<h3>Vos fichiers</h3>

<?php if (!empty($files)) : ?>
    <table class="file-table">
        <thead>
            <tr>
                <th>Filename</th>
                <th>Description</th>
                <th>Size</th>
                <th>Download count</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($files as $file) : ?>
                <tr>
                    <td><a href="/file/<?= $file['id'] ?>"><?= htmlspecialchars($file['filename'], ENT_QUOTES) ?></a></td>
                    <td><?= htmlspecialchars($file['description'], ENT_QUOTES) ?></td>
                    <td><?= htmlspecialchars($file['size'], ENT_QUOTES) ?></td>
                    <td><?= htmlspecialchars($file['downloadCount'], ENT_QUOTES) ?></td>
                    <td>
                        <a href="/download/<?= htmlspecialchars($file['id'], ENT_QUOTES) ?>" target="_blank">Télécharger</a>
                        <form action="/delete/<?= htmlspecialchars($file['id'], ENT_QUOTES) ?>" method="post">
                            <input type="hidden" name="csrf" value="<?= $csrf_delete ?? '' ?>" />
                            <button type="submit">Supprimer</button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
<?php else : ?>
    <p>Vous n'avez pas de fichiers</p>
<?php endif; ?>

<h3>Télécharger un fichier</h3>

<form action="/upload" method="post" enctype="multipart/form-data">
    <div>
        <input type="file" name="file" />
    </div>
    <label>
        <textarea name="description" placeholder="Description" cols="30" rows="10"></textarea>
    </label>
    <div>
        <button type="submit">Télécharger</button>
    </div>
    <input type="hidden" name="csrf" value="<?= $csrf_upload ?? '' ?>" />
</form>
<?php if (!empty($messages)) : ?>
    <hr />
    <?php foreach ($messages as $message) : ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>