<?php

namespace App\Models;

use PDO;

class Comment extends AbstractModel
{

    public function get(int $id): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM comment WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        $query->execute();
        return $query->fetch(PDO::FETCH_ASSOC);
    }

    public function getByUser(int $userId): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM comment WHERE user_id = :user_id ORDER BY created_date DESC');
        $query->bindParam(':user_id', $userId, PDO::PARAM_INT);
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getByFile(int $fileId): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM comment WHERE file_id = :file_id ORDER BY created_date DESC');
        $query->bindParam(':file_id', $fileId, PDO::PARAM_INT);
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function getAll(): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM comment');
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function create(
        int $userId,
        string $content,
        int $fileId,
    ): bool
    {
        $query = $this->pdo->prepare('INSERT INTO comment ( user_id, content, file_id, created_date ) VALUES (:user_id, :content, :file_id, :user_id, :created_date)');
        return $query->execute([
            'user_id' => $userId,
            'content' => $content,
            'file_id' => $fileId,
            'created_date' => date('Y-m-d H:i:s')
        ]);
    }

    public function delete(int $id): bool
    {
        $query = $this->pdo->prepare('DELETE FROM comment WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        return $query->execute();
    }
}