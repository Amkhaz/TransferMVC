# Transfer MVC

## Description

This project is a base for the development of a PHP MVC application..

## Pre-requisites

To install the project, you need to have the following tools installed on your computer:

- PHP 8.1 or higher
- Composer

You also need to activate the following PHP extensions:

- pdo_mysql
- zip
- intl
- curl

## Configuration

Once the project is installed, you need to configure the application and the database connection. To do so, you need
to copy the files `config/app.dist.php` and `config/database.dist.php` to `config/app.php` and `config/database.php`:

```bash
cp config/app.dist.php config/app.php
cp config/database.dist.php config/database.php
```

Then you need to edit the files `config/app.php` and `config/database.php` to set the correct values.

## Docker MySQL

If you need a MySQL database for the project development, you can use the following command to start a MySQL server
in a Docker:

```bash
docker run -d --name mysql -p 3306:3306 -e MYSQL_ROOT_PASSWORD=db-password mysql
```

Then you need to create a database with the name of your choice, and a user with a password. Then, you can grant to
this user all privileges on the database.

```bash
mariadb -h 127.0.0.1 -u root -p
```

```sql
CREATE DATABASE database_name;
CREATE USER 'username'@'%' IDENTIFIED BY 'password';
GRANT ALL PRIVILEGES ON database_name.* TO 'username'@'%';
```

If you need to import a SQL file, you can use the following command:

```bash
mariadb -h 127.0.0.1 -D database -u root -p < setup/database.sql
```

## Dev server

To start the application, you can use the following command:

```bash
php -S localhost:8000 -t public
```

Then you can open the following URL in your browser: http://localhost:8000

## Application structure

The application is structured as follows:

- `config/`: Configuration files for the app and the database
- `public/`: Directory accessible from the web
- `src/`: Application files
    - `Controllers/`: Controllers
    - `Models/`: Interactions with the database
    - `Router/`: Routing of the application (what controller and method to call for a given URL)
    - `Services/`: Other classes used by the application
    - `Views/`: Views of the application (code that will be displayed to the user)
- `var/`: Logs of the application
- `vendor/`: Dependencies installed with composer

The application uses the following libraries:

- symfony/http-foundation: To manage HTTP requests and responses
- phroute/phroute: To manage the routing of the application

### Router

The router is managed in the file `src/Router/router.php`. It is configured to use the controllers. You need to add
the routes of your application in this file.

Example:

```php
// Simple route with a controller and a method corresponding to the URL /
$router->get('/', function () {
    $controller = new HomeController();
    $controller->index();
});

// Route with a parameter (id) and a controller and a method corresponding to the URL /model/{id}
// the parameter is passed to the method
$router->get('/model/{id}', function ($id) {
    $controller = new HomeController();
    $controller->getModel($id);
});
```

### Controllers

The controllers are located in the directory `src/Controllers`. They are used to manage the requests and the responses
of the application. They are called by the router.

Example of a method in a controller:

```php
    public function index(): Response
    {
        // Get the name parameter from the request thanks to the http-foundation library
        // the request parameter is part of the parent AbstractController class and corresponds to the Request
        // object of the http-foundation library
        $name = $this->request->get('name', 'World');
        
        // We create a response with the rendered view. The render method is part of the parent AbstractController
        // and build the HTML content to display from the views of the application located in the Views directory
        $response = new Response(
            $this->render('Home/index', [
                'name' => $name,
            ])
        );

        // We then return the response that will be sent to the user's browser
        return $response->send();
    }
```

### Models

The models are located in the directory `src/Models`. They are used to interact with the database. They are called by
the controllers.

Example of a controller calling data through a model:

```php
public function getModel($id): Response
{
    // Instantiate the model Example from the Models directory and call the method get with the parameter $id provided
    // by the router. The method get will return an array with the data corresponding to the id in the database
    // Here we cast the id to an int because this is what the method get is expecting
    $model = new Example();
    $model->get((int)$id);

    // We create a response with the rendered view.
    $response = new Response(
        $this->render('Home/index', [
            'model' => $model,
        ])
    );

    // We then return the response that will be sent to the user's browser
    return $response->send();
}
```

The models are using PDO to interact with the database. The PDO object is instantiated in the parent AbstractModel.

Example of a model method:

```php
    public function get(int $id): array|bool
    {
        // We prepare the SQL query with a parameter (:id) that will be replaced by the value of the variable $id
        // We then execute the query
        $query = $this->pdo->prepare('SELECT * FROM example WHERE id = :id');
        $query->bindParam(':id', $id, PDO::PARAM_INT);
        $query->execute();
        
        // We return the result of the query as an associative PHP array
        return $query->fetch(PDO::FETCH_ASSOC);
    }
```

### Views

The views are located in the directory `src/Views`. They are used to display the HTML content to the user. They are
called by the controllers.

Example of a view:

```php
<!-- We include the base HTML header of the application (the top of the content) -->
<?php include_once __DIR__ . '/../Commons/base_header.php'; ?>

<p>Home</p>

<!-- If the variable $name is set, we display the content of the variable -->
<?php if (isset($name)): ?>
    <p>Hello <?= htmlspecialchars($name, ENT_QUOTES) ?>!</p>
<?php endif; ?>

<!-- We include the base HTML footer of the application (the bottom of the content) -->
<?php include_once __DIR__ . '/../Commons/base_footer.php'; ?>
```

### Services

The services are located in the directory `src/Services`. They are used to manage other classes of the application.

## License

This code is licensed under the [MIT License](https://opensource.org/licenses/MIT).
