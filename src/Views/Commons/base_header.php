<!doctype html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Transfer MVC PHP Application</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/water.css@2/out/light.css">
    <link rel="stylesheet" type="text/css" href="/css/style.css">
</head>

<body>
    <header>
        <div class="title">
            <h1>Transfer MVC PHP Application</h1>
        </div>
    </header>

    <?php

    use App\Services\Security;

    if (Security::isConnected()) {
        include_once __DIR__ . '/menu_connected.php';
    } else {
        include_once __DIR__ . '/menu_not_connected.php';
    }
    ?>


    <main>