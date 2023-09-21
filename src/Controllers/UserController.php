<?php

namespace App\Controllers;

use App\Models\User;
use App\Services\Message;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;

class UserController extends AbstractController
{

    public function register(): Response
    {
        $response = new Response(
            $this->render('User/register')
        );

        return $response->send();
    }

    public function registerProcess(): Response
    {
        $userForm = [
            "email" => $this->request->get('email'),
            "password" => $this->request->get('password'),
            "passwordConfirm" => $this->request->get('password_confirm'),
            "lastname" => $this->request->get('lastname'),
            "firstname" => $this->request->get('firstname'),
        ];

        $error = [];

        // Check if all fields are filled
        foreach ($userForm as $key => $value)
            if (empty($value)) $error[] = $key . ' is empty';

        if (!filter_var($userForm['email'], FILTER_VALIDATE_EMAIL)) {
            $error[] = 'email is not valid';
        }

        // Check if password and passwordConfirm are the same
        if ($userForm['password'] !== $userForm['passwordConfirm']) $error[] = 'passwords are not the same';

        $userModel = new User();
        if ($userModel->isEmailExists($userForm['email'])) $error[] = 'email already exists';

        // TODO: check password strength...

        if (!empty($error)) {
            return $this->errorForm($error, $userForm);
        }

        $userCreation = $userModel->create(
            $userForm['email'],
            password_hash($userForm['password'], PASSWORD_DEFAULT),
            $userForm['lastname'],
            $userForm['firstname']
        );

        if (!$userCreation) {
            return $this->errorForm(['user creation failed'], $userForm);
        }

        $response = new Response(
            $this->render('User/register', [
                'success' => 'User has been created, please login'
            ])
        );

        return $response->send();

    }
    public function viewProfile() {
        // Retrieve the logged-in user's information
        $userId = $_SESSION['user']['id'];  // Assuming you store user's ID in session when they login.
        $userModel = new User();
        $userInfo = $userModel->get($userId);


        $messageService = new Message();

        $response = new Response(
            $this->render('User/user', [
                'user' => $userInfo,
                'messages' => $messageService->getMessages()

            ])
        );

        return $response->send();

        // And so on for other user details you wish to display
    }


    public function changePassword()
    {
        $userId = $_SESSION['user']['id'];
        $userModel = new User();

        $oldPassword = $_POST['old_password'];
        $newPassword = $_POST['new_password'];
        $verifyPassword = $_POST['confirm_password'];

        $messageService = new Message();

        // Check if the old password matches the one in the database
        if (!$userModel->checkPassword($userId, $oldPassword)) {
            $messageService->addMessage("Old password doesn't match");
            $response = new RedirectResponse('/user');
            return $response->send();
        }

        // Check if the new password matches the verification password
        if ($newPassword !== $verifyPassword) {
            $messageService->addMessage("New Password doesn't match");
            $response = new RedirectResponse('/user');
            return $response->send();
        }

        // Update the password in the database
        $success = $userModel->updatePassword($userId, $newPassword);


        $messageService->addMessage($success ? 'Password updated successfully': 'Failed to update password');
        $response = new RedirectResponse('/user');
        return $response->send();

    }

    private function errorForm(array $errors, array $form = []): Response
    {
        $response = new Response(
            $this->render('User/register', [
                'error' => $errors,
                'userForm' => $form
            ])
        );
        return $response->send();
    }

}