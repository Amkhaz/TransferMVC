<?php

namespace App\Controllers;

use App\Models\Comment;
use App\Models\File;
use App\Services\Csrf;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class CommentController extends AbstractController
{

    public function add(string $token): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $fileModel = new File();
        $file = $fileModel->getByToken($token);

        if (!$file || !$file['isPublic']) {
            return $this->error('File not found', 404);
        }

        $commentModel = new Comment();
        if (!$commentModel->create((int)$_SESSION['user']['id'], $this->request->get('content'), (int)$file['id'])) {
            $this->logger->log("Unable to add comment : Database error");
        }

        $response = new RedirectResponse('/dl/' . $token);
        return $response->send();
    }

    public function delete(int $id): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $commentModel = new Comment();
        $comment = $commentModel->get($id);

        if (!$comment) {
            return $this->error('Comment not found', 404);
        }

        $fileModel = new File();
        $file = $fileModel->get($comment['file_id']);

        if (!$file || $file['user_id'] !== $_SESSION['user']['id']) {
            return $this->error('Unauthorized', 401);
        }

        if (!$commentModel->delete($id)) {
            $this->logger->log("Unable to delete comment : Database error");
        }

        $response = new RedirectResponse('/file/' . $file['id']);
        return $response->send();
    }

}