<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<h2>Dashboard</h2>

<p>Hello <?= htmlspecialchars($name ?? '', ENT_QUOTES) ?>!</p>

<h3>Your files</h3>

<?php if (!empty($files)): ?>
    <table>
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
        <?php foreach ($files as $file): ?>
            <tr>
                <td><a href="/file/<?= $file['id'] ?>"><?= htmlspecialchars($file['filename'], ENT_QUOTES) ?></a></td>
                <td><?= htmlspecialchars($file['description'], ENT_QUOTES) ?></td>
                <td><?= htmlspecialchars($file['size'], ENT_QUOTES) ?></td>
                <td><?= htmlspecialchars($file['downloadCount'], ENT_QUOTES) ?></td>
                <td>
                    <a href="/download/<?= htmlspecialchars($file['id'], ENT_QUOTES) ?>" target="_blank">Download</a>
                    <form action="/delete/<?= htmlspecialchars($file['id'], ENT_QUOTES) ?>" method="post">
                        <input type="hidden" name="csrf" value="<?= $csrf_delete ?? '' ?>" />
                        <button type="submit">Delete</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
<?php else: ?>
    <p>You have no files</p>
<?php endif; ?>

<h3>Upload a file</h3>

<form action="/upload" method="post" enctype="multipart/form-data">
    <div>
        <input type="file" name="file"/>
    </div>
    <label>
        <textarea name="description" placeholder="Description" cols="30" rows="10"></textarea>
    </label>
    <div>
        <button type="submit">Upload</button>
    </div>
    <input type="hidden" name="csrf" value="<?= $csrf_upload ?? '' ?>" />
</form>
<?php if (!empty($messages)): ?>
    <hr/>
    <?php foreach ($messages as $message): ?>
        <div><?= htmlspecialchars($message) ?></div>
    <?php endforeach; ?>
<?php endif; ?>

<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>
