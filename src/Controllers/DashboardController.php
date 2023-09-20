<?php

namespace App\Controllers;

use App\Models\Comment;
use App\Models\File;
use App\Services\Csrf;
use App\Services\Security;
use Symfony\Component\HttpFoundation\Response;

class DashboardController extends AbstractController
{
    public function index(): Response
    {
        $files = (new File())->getByUser((int)$_SESSION['user']['id']);

        $response = new Response(
            $this->render('Dashboard/index', [
                "name" => $_SESSION['user']['firstname'],
                "files" => $files,
                "csrf_delete" => (new Csrf())->generate(),
                "csrf_upload" => (new Csrf())->generate()
            ])
        );

        return $response->send();
    }

    public function show($id): Response
    {
        $fileModel = new File();
        $file = $fileModel->get($id);

        if (!$file || !file_exists($file['path']) || $file['user_id'] !== $_SESSION['user']['id']) {
            return $this->error('File not found');
        }

        $commentModel = new Comment();
        $security = new Security();

        $response = new Response(
            $this->render('Dashboard/show', [
                "file" => $file,
                "base_url" => $this->config['url'],
                "csrf" => (new Csrf())->generate(),
                "comments" => $commentModel->getByFile($id),
            ])
        );

        return $response->send();
    }

}