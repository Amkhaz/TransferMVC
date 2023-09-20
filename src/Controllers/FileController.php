<?php

namespace App\Controllers;

use App\Models\File;
use App\Services\Csrf;
use App\Services\Message;
use App\Services\Security;
use App\Services\Upload;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use App\Models\Comment;

class FileController extends AbstractController
{

    public function upload(): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $file = $this->request->files->get('file');

        if (!$file) {
            $this->logger->log("Unable to upload file : No file");
            return $this->error('No file uploaded', 400);
        }

        $filename = $file->getClientOriginalName();
        $fileSize = $file->getSize();

        $upload = new Upload();
        $path = $upload->upload($file);
        if (!$path) {
            $this->logger->log("Unable to upload file : File error");
            return $this->error('An error occurred', 500);
        }

        $fileModel = new File();
        $result = $fileModel->create(
            $path,
            $filename,
            $this->request->request->get('description'),
            (int)$_SESSION['user']['id'],
            null,
            null,
            false,
            false,
            0,
            $fileSize,
        );

        if (!$result) {
            $this->logger->log("Unable to upload file : Database error");
            return $this->error('An error occurred', 500);
        }

        $response = new RedirectResponse('/dashboard');
        return $response->send();
    }

    public function downloadUser($id): Response
    {
        $fileModel = new File();
        $file = $fileModel->get($id);

        if (!$file || !file_exists($file['path']) || $file['user_id'] !== $_SESSION['user']['id']) {
            $response = new Response('File not found', 404);
            return $response->send();
        }

        $upload = new Upload();
        return $upload->download($file['path'], $file['filename']);
    }

    public function delete($id): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $fileModel = new File();
        $file = $fileModel->get($id);

        if (!$file || !file_exists($file['path']) || $file['user_id'] !== $_SESSION['user']['id']) {
            $this->logger->log("Unable to delete file with id $id : File not found");
            return $this->error('File not found');
        }

        $upload = new Upload();
        if (!$upload->delete($file['path'])) {
            $this->logger->log("Unable to delete file with id $file[id] on disk");
            return $this->error('An error occurred', 500);
        }

        if (!$fileModel->delete($id)) {
            $this->logger->log("Unable to delete file with id $file[id] in database");
            return $this->error('An error occurred', 500);
        }

        $response = new RedirectResponse('/dashboard');
        return $response->send();

    }

    public function makePublic($id): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $fileModel = new File();
        $file = $fileModel->get($id);
        if (!$file || !file_exists($file['path']) || $file['user_id'] !== $_SESSION['user']['id']) {
            return $this->error('File not found');
        }

        $isPublic = $this->request->get('isPublic') === 'on';
        $hasPassword = $isPublic && $this->request->get('hasPassword') === 'on';
        $hashedPassword = $hasPassword ? password_hash($this->request->get('password'), PASSWORD_DEFAULT) : null;

        $token = null;
        if ($isPublic) {
            $token = !$file['isPublic'] ? bin2hex(random_bytes(16)) : $file['token'];
        }

        // TODO Check if the token already exist

        $fileModel = new File();

        if (!$fileModel->makePublic((int)$id, $isPublic, $token, $hasPassword, $hashedPassword)) {
            $this->logger->log("Unable to make file with id $id public");
            return $this->error('An error occurred', 500);
        }

        $response = new RedirectResponse('/file/' . $id);
        return $response->send();
    }

    public function downloadPublic($token): Response
    {
        $fileModel = new File();
        $file = $fileModel->getByToken($token);

        if (!$file || !$file['isPublic']) {
            return $this->error('File not found');
        }

        $commentModel = new Comment();
        $security = new Security();

        $response = new Response(
            $this->render('Home/file', [
                'file' => $file,
                'messages' => Message::getMessages(),
                'csrf' => (new Csrf())->generate(),
                'comments' => $commentModel->getByFile($file['id']),
                "isConnected" => $security->isConnected(),
            ])
        );
        return $response->send();
    }

    public function downloadPublicProcess($token): Response
    {
        $fileModel = new File();
        $file = $fileModel->getByToken($token);

        if (!$file || !$file['isPublic']) {
            $this->error('File not found');
        }

        if ($file['hasPassword'] && !password_verify($this->request->get('password'), $file['password'])) {
            // TODO Redirect with error
            Message::addMessage('Invalid password');
            return (new RedirectResponse('/dl/' . $token))->send();
        }

        $fileModel->incrementDownloadCount((int)$file['id']);

        $upload = new Upload();
        return $upload->download($file['path'], $file['filename']);
    }
}