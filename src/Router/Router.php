<?php

namespace App\Router;

use App\Controllers\DashboardController;
use App\Controllers\FileController;
use App\Controllers\HomeController;
use App\Controllers\LoginController;
use App\Controllers\UserController;
use App\Services\Security;
use Phroute\Phroute\Dispatcher;
use Phroute\Phroute\Exception\HttpRouteNotFoundException;
use Phroute\Phroute\RouteCollector;
use Symfony\Component\HttpFoundation\RedirectResponse;

class Router
{
    public function run(): void
    {
        $router = new RouteCollector();

        /**
         * Routes definition
         */

        $router->get('/', function () {
            $controller = new HomeController();
            $controller->index();
        });

        $router->get('/register', function () {
            $controller = new UserController();
            $controller->register();
        });

        $router->post('/register', function () {
            if (Security::isConnected()) {
                $response = new RedirectResponse('/dashboard');
                return $response->send();
            }

            $controller = new UserController();
            return $controller->registerProcess();
        });

        $router->get('/login', function () {
            $controller = new LoginController();
            $controller->login();
        });

        $router->post('/login_check', function () {
            $controller = new LoginController();
            $controller->loginCheck();
        });

        $router->get('/logout', function () {
            session_destroy();
            $response = new RedirectResponse('/');
            return $response->send();
        });

        $router->get('/dashboard', function () {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new DashboardController();
            return $controller->index();
        });

        $router->post('/upload', function () {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new FileController();
            return $controller->upload();
        });

        $router->get('/download/{id}', function ($id) {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new FileController();
            return $controller->downloadUser($id);
        });

        $router->post('/delete/{id}', function ($id) {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new FileController();
            return $controller->delete($id);
        });

        $router->get('/file/{id}', function ($id) {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new DashboardController();
            return $controller->show($id);
        });

        $router->post('/public/{id}', function ($id) {
            if (!Security::isConnected()) {
                $response = new RedirectResponse('/login');
                return $response->send();
            }

            $controller = new FileController();
            return $controller->makePublic($id);
        });

        $router->get('/dl/{token}', function ($token) {
            $controller = new FileController();
            return $controller->downloadPublic($token);
        });

        $router->post('/dl/{token}', function ($token) {
            $controller = new FileController();
            return $controller->downloadPublicProcess($token);
        });

        
        $router->post('/file/update-description', function () {
            
            $fileId = $_POST['file_id'];
            $newDescription = $_POST['new_description'];

            
            $controller = new FileController();
            $result = $controller->updateDescription($fileId, $newDescription);

            
            if ($result) {
                $response = new RedirectResponse('/file/' . $fileId);
                return $response->send();
            } else {
             
            }
        });

        /**
         * End of routes definition
         */

        try {
            $dispatcher = new Dispatcher($router->getData());
            $dispatcher->dispatch($_SERVER['REQUEST_METHOD'], parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH));
        } catch (HttpRouteNotFoundException $e) {
            $controller = new HomeController();
            $controller->error404();
        }
    }
}
