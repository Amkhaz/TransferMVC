<?php

namespace App\Models;

use PDO;

class User extends AbstractModel
{

    public function get(int $id): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM user WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        $query->execute();
        return $query->fetch(PDO::FETCH_ASSOC);
    }

    public function getByEmail(string $email): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM user WHERE email = :email');
        $query->bindParam(':email', $email);
        $query->execute();
        return $query->fetch(PDO::FETCH_ASSOC);
    }

    public function isEmailExists(string $email): bool
    {
        $query = $this->pdo->prepare('SELECT count(id) FROM user WHERE email = :email');
        $query->bindParam(':email', $email);
        $query->execute();

        return $query->fetch()[0] > 0;
    }

    public function getAll(): array|bool
    {
        $query = $this->pdo->prepare('SELECT * FROM user');
        $query->execute();
        return $query->fetchAll(PDO::FETCH_ASSOC);
    }

    public function create(
        string $email,
        string $password,
        string $lastname,
        string $firstname,
        int $isPayed = 0
    ): bool
    {
        $query = $this->pdo->prepare('INSERT INTO user (email, password, lastname, firstname, isPayed) VALUES (:email, :password, :lastname, :firstname, :isPayed)');

        return $query->execute([
            ':email' => $email,
            ':password' => $password,
            ':lastname' => $lastname,
            ':firstname' => $firstname,
            ':isPayed' => $isPayed
        ]);
    }

    public function update(
        int $id,
        string $email,
        string $password,
        string $lastname,
        string $firstname,
        int $isPayed = 0
    ): bool
    {
        $query = $this->pdo->prepare('UPDATE user SET email = :email, password = :password, lastname = :lastname, firstname = :firstname, isPayed = :isPayed WHERE id = :id');

        return $query->execute([
            ':id' => $id,
            ':email' => $email,
            ':password' => $password,
            ':lastname' => $lastname,
            ':firstname' => $firstname,
            ':isPayed' => $isPayed
        ]);
    }

    public function delete(int $id): bool
    {
        $query = $this->pdo->prepare('DELETE FROM user WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        return $query->execute();
    }
    public function checkPassword(int $userId, string $password): bool
    {
        $user = $this->get($userId);
        if (!$user) {
            return false;
        }

        // Verify the provided password with the one in the database
        return password_verify($password, $user['password']);
    }

    public function updatePassword(int $userId, string $newPassword): bool
    {
        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

        $query = $this->pdo->prepare('UPDATE user SET password = :password WHERE id = :id');
        $query->bindParam(':id', $userId, PDO::PARAM_INT);
        $query->bindParam(':password', $hashedPassword);

        return $query->execute();
    }

}