-- --------------------------------------------------------
-- Hôte:                         127.0.0.1
-- Version du serveur:           8.1.0 - MySQL Community Server - GPL
-- SE du serveur:                Linux
-- HeidiSQL Version:             12.5.0.6677
-- --------------------------------------------------------
/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8 */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
-- Listage de la structure de la table projet2. comment
DROP TABLE IF EXISTS `comment`;
CREATE TABLE IF NOT EXISTS `comment` (
                                         `id` int NOT NULL AUTO_INCREMENT,
                                         `file_id` int NOT NULL,
                                         `content` text CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL,
                                         `user_id` int NOT NULL,
                                         `created_date` datetime NOT NULL,
                                         PRIMARY KEY (`id`),
                                         KEY `fk_file` (`file_id`),
                                         KEY `fk_user` (`user_id`),
                                         CONSTRAINT `fk_file` FOREIGN KEY (`file_id`) REFERENCES `file` (`id`),
                                         CONSTRAINT `fk_user` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- Les données exportées n'étaient pas sélectionnées.
-- Listage de la structure de la table projet2. file
DROP TABLE IF EXISTS `file`;
CREATE TABLE IF NOT EXISTS `file` (
                                      `id` int NOT NULL AUTO_INCREMENT,
                                      `path` varchar(255) NOT NULL,
                                      `filename` varchar(255) NOT NULL,
                                      `description` text,
                                      `user_id` int NOT NULL,
                                      `token` varchar(255) DEFAULT NULL,
                                      `password` varchar(255) DEFAULT NULL,
                                      `isPublic` tinyint(1) DEFAULT '0',
                                      `hasPassword` tinyint(1) DEFAULT '0',
                                      `downloadCount` int NOT NULL DEFAULT '0',
                                      `size` int NOT NULL,
                                      `createdAt` datetime NOT NULL,
                                      PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=13 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- Les données exportées n'étaient pas sélectionnées.
-- Listage de la structure de la table projet2. user
DROP TABLE IF EXISTS `user`;
CREATE TABLE IF NOT EXISTS `user` (
                                      `id` int NOT NULL AUTO_INCREMENT,
                                      `email` varchar(255) NOT NULL,
                                      `password` varchar(255) NOT NULL,
                                      `lastname` varchar(255) DEFAULT NULL,
                                      `firstname` varchar(255) DEFAULT NULL,
                                      `isPayed` tinyint(1) NOT NULL DEFAULT '0',
                                      `isAdmin` tinyint(1) NOT NULL DEFAULT '0',
                                      PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
-- Les données exportées n'étaient pas sélectionnées.
/*!40103 SET TIME_ZONE=IFNULL(@OLD_TIME_ZONE, 'system') */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IFNULL(@OLD_FOREIGN_KEY_CHECKS, 1) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40111 SET SQL_NOTES=IFNULL(@OLD_SQL_NOTES, 1) */;





