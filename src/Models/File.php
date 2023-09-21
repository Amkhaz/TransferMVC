<?php

namespace App\Models;

use PDO;

class File extends AbstractModel
{

    public function get(int $id): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM file WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        $query->execute();
        return $query->fetch(PDO::FETCH_ASSOC);
    }

    public function getByToken(string $token): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM file WHERE token = :token');
        $query->bindParam(':token', $token);
        $query->execute();
        return $query->fetch(PDO::FETCH_ASSOC);
    }

    public function getByUser(int $userId): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM file WHERE user_id = :user_id ORDER BY createdAt DESC');
        $query->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getAll(): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM file');
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function create(
        string $path,
        string $filename,
        string $description,
        int $userId,
        string $token = null,
        string $password = null,
        bool $isPublic = false,
        bool $hasPassword = false,
        int $downloadCount = 0,
        int $size = 0
    ): bool
    {
        $query = $this->pdo->prepare('INSERT INTO file (path, filename, description, user_id, token, password, isPublic, hasPassword, downloadCount, size, createdAt) VALUES (:path, :filename, :description, :user_id, :token, :password, :isPublic, :hasPassword, :downloadCount, :size, :createdAt)');
        return $query->execute([
            'path' => $path,
            'filename' => $filename,
            'description' => $description,
            'user_id' => $userId,
            'token' => $token,
            'password' => $password,
            'isPublic' => $isPublic ? 1 : 0,
            'hasPassword' => $hasPassword ? 1 : 0,
            'downloadCount' => $downloadCount,
            'size' => $size,
            'createdAt' => date('Y-m-d H:i:s')
        ]);
    }

    public function update(
        int $id,
        string $path,
        string $filename,
        string $description,
        int $userId,
        string $token = null,
        string $password = null,
        bool $isPublic = false,
        bool $hasPassword = false,
        int $downloadCount = 0,
        int $size = 0
    ): bool
    {
        $query = $this->pdo->prepare('UPDATE file SET path = :path, filename = :filename, description = :description, user_id = :user_id, token = :token, password = :password, isPublic = :isPublic, hasPassword = :hasPassword, downloadCount = :downloadCount, size = :size WHERE id = :id');
        return $query->execute([
            'id' => $id,
            'path' => $path,
            'filename' => $filename,
            'description' => $description,
            'user_id' => $userId,
            'token' => $token,
            'password' => $password,
            'isPublic' => $isPublic ? 1 : 0,
            'hasPassword' => $hasPassword ? 1 : 0,
            'downloadCount' => $downloadCount,
            'size' => $size
        ]);
    }


    public function delete(int $id): bool
    {
        $query = $this->pdo->prepare('DELETE FROM file WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        return $query->execute();
    }

    public function makePublic(int $id, bool $isPublic, string $token = null, bool $hasPassword = false, string $password = null): bool
    {
        $query = $this->pdo->prepare('UPDATE file SET isPublic = :isPublic, token = :token, hasPassword = :hasPassword, password = :password WHERE id = :id');
        return $query->execute([
            'id' => $id,
            'isPublic' => $isPublic ? 1 : 0,
            'token' => $token,
            'hasPassword' => $hasPassword ? 1 : 0,
            'password' => $password
        ]);
    }

    public function incrementDownloadCount(int $id): bool
    {
        $query = $this->pdo->prepare('UPDATE file SET downloadCount = downloadCount + 1 WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        return $query->execute();
    }
    public function getUsedSize(int $id): int {
        $query = $this->pdo->prepare('SELECT SUM(size) FROM file WHERE user_id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        $query->execute();
        return $query->fetch()[0] ?? 0;
    }

    public function updateDescription(int $fileId, string $newDescription, int $user_id): bool
    {
        $query = $this->pdo->prepare('UPDATE file SET description = :description WHERE id = :id AND user_id = :user_id');
        return $query->execute([
            'id' => $fileId,
            'description' => $newDescription,
            'user_id' => $user_id
        ]);
    }
}