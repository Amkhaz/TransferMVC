<?php

namespace App\Controllers;

use App\Models\User;
use App\Services\Csrf;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class LoginController extends AbstractController
{

    public function login(): Response
    {
        $response = new Response(
            $this->render('Login/login', [
                "csrf" => (new Csrf())->generate(),
            ])
        );

        return $response->send();
    }

    public function loginCheck(): Response
    {
        if (!(new Csrf())->check($this->request->get('csrf'))) {
            return $this->error('Invalid CSRF token', 400);
        }

        $email = $this->request->get('email');
        $password = $this->request->get('password');

        if (empty($email) || empty($password)) {
            return $this->errorForm('Email ou mot de passe vide', $email);
        }

        $model = new User();
        $user = $model->getByEmail($email);

        if (!$user) {
            return $this->errorForm('Email ou mot de passe incorrect', $email);
        }

        if (!password_verify($password, $user['password'])) {
            return $this->errorForm('Email ou mot de passe incorrect', $email);
        }

        // Renew session token
        session_regenerate_id(true);

        $_SESSION['user'] = [
            'id' => $user['id'],
            'email' => $user['email'],
            'lastname' => $user['lastname'],
            'firstname' => $user['firstname'],
            'isAdmin' => $user['isAdmin'],
        ];

        $response = new RedirectResponse('/dashboard');
        return $response->send();
    }

    private function errorForm(string $error, string $email): Response
    {
        $response = new Response(
            $this->render('Login/login', [
                'error' => $error,
                'email' => $email,
            ])
        );

        return $response->send();
    }

}