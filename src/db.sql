CREATE TABLE roles (
	id_rol INT AUTO_INCREMENT PRIMARY KEY,
    rol_name VARCHAR(255) NOT NULL
);

CREATE TABLE users (
	id_user INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(255),
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    create_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active TINYINT(1) DEFAULT 1,
    is_verified TINYINT(1) DEFAULT 0,
    role_id INT NOT NULL,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (role_id) REFERENCES roles(id_rol)
);

CREATE TABLE user_information (
    id_info INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    company VARCHAR(255) NULL,
    phone VARCHAR(20) NULL,
    address VARCHAR(255) NULL,
    birthdate DATE NULL,
    deleted_at TIMESTAMP NULL,
    FOREIGN KEY (user_id) REFERENCES users(id_user)
);

CREATE TABLE email_verification (
    id_verification INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    verification_token VARCHAR(255) NOT NULL,
    is_verified TINYINT(1) DEFAULT 0,
    verification_expires DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id_user)
);

CREATE TABLE password_resets (
    id_reset INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    reset_password_token VARCHAR(255) NOT NULL,
    reset_password_expires DATETIME NOT NULL,
    password_reset_count INT DEFAULT 0,
    reset_password_block_until DATETIME NULL,
    FOREIGN KEY (user_id) REFERENCES users(id_user)
);



////////////////////////// INSERTS //////////////////////////
-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 10-03-2025 a las 03:14:23
-- Versión del servidor: 10.4.32-MariaDB
-- Versión de PHP: 8.2.12

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


CREATE TABLE `email_verification` (
  `id_verification` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `verification_token` varchar(255) NOT NULL,
  `verification_expires` datetime NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `password_resets`
--

CREATE TABLE `password_resets` (
  `id_reset` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `reset_password_token` varchar(255) NOT NULL,
  `reset_password_expires` datetime NOT NULL,
  `password_reset_count` int(11) DEFAULT 0,
  `reset_password_block_until` datetime DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `password_resets`
--

INSERT INTO `password_resets` (`id_reset`, `user_id`, `reset_password_token`, `reset_password_expires`, `password_reset_count`, `reset_password_block_until`) VALUES
(13, 22, 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImVkdWFybXVub3oxNzhAZ21haWwuY29tIiwiaWF0IjoxNzQwMzcxNDY1LCJleHAiOjE3NDAzNzIzNjV9.23ENA7pd86K1epUjg8O6LqCqHF7pYAcXpEWq63ztivo', '2025-02-23 20:46:05', 1, NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `roles`
--

CREATE TABLE `roles` (
  `id_rol` int(11) NOT NULL,
  `rol_name` varchar(255) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `roles`
--

INSERT INTO `roles` (`id_rol`, `rol_name`) VALUES
(1, 'administrador'),
(2, 'super'),
(3, 'client');

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `users`
--

CREATE TABLE `users` (
  `id_user` int(11) NOT NULL,
  `full_name` varchar(255) DEFAULT NULL,
  `email` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `create_at` timestamp NOT NULL DEFAULT current_timestamp(),
  `last_login` timestamp NULL DEFAULT NULL,
  `is_active` tinyint(1) DEFAULT 1,
  `is_verified` tinyint(4) NOT NULL DEFAULT 0,
  `role_id` int(11) NOT NULL,
  `deleted_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `users`
--

INSERT INTO `users` (`id_user`, `full_name`, `email`, `password`, `create_at`, `last_login`, `is_active`, `is_verified`, `role_id`, `deleted_at`) VALUES
(22, 'agapito lopez perez', 'agapito@gmail.com', '$2b$10$YVF.02GKcoG360WeUv090e1GeFaYBvTMWXLBzCkt58hvmrwGgEzhS', '2025-02-24 04:13:41', '2025-03-10 02:09:59', 1, 1, 2, NULL);

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `user_information`
--

CREATE TABLE `user_information` (
  `id_info` int(11) NOT NULL,
  `user_id` int(11) NOT NULL,
  `full_name` varchar(255) DEFAULT NULL,
  `company` varchar(255) DEFAULT NULL,
  `phone` varchar(20) DEFAULT NULL,
  `address` varchar(255) DEFAULT NULL,
  `birthdate` date DEFAULT NULL,
  `deleted_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Volcado de datos para la tabla `user_information`
--

INSERT INTO `user_information` (`id_info`, `user_id`, `full_name`, `company`, `phone`, `address`, `birthdate`, `deleted_at`) VALUES
(21, 22, 'agapito lopez perez', 'agapitoSystem', '55555555', 'av tangamandapioo', '2016-03-01', NULL);

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `email_verification`
--
ALTER TABLE `email_verification`
  ADD PRIMARY KEY (`id_verification`),
  ADD KEY `user_id` (`user_id`);

--
-- Indices de la tabla `password_resets`
--
ALTER TABLE `password_resets`
  ADD PRIMARY KEY (`id_reset`),
  ADD KEY `user_id` (`user_id`);

--
-- Indices de la tabla `roles`
--
ALTER TABLE `roles`
  ADD PRIMARY KEY (`id_rol`);

--
-- Indices de la tabla `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id_user`),
  ADD KEY `role_id` (`role_id`);

--
-- Indices de la tabla `user_information`
--
ALTER TABLE `user_information`
  ADD PRIMARY KEY (`id_info`),
  ADD KEY `user_id` (`user_id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `email_verification`
--
ALTER TABLE `email_verification`
  MODIFY `id_verification` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=25;

--
-- AUTO_INCREMENT de la tabla `password_resets`
--
ALTER TABLE `password_resets`
  MODIFY `id_reset` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- AUTO_INCREMENT de la tabla `roles`
--
ALTER TABLE `roles`
  MODIFY `id_rol` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- AUTO_INCREMENT de la tabla `users`
--
ALTER TABLE `users`
  MODIFY `id_user` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- AUTO_INCREMENT de la tabla `user_information`
--
ALTER TABLE `user_information`
  MODIFY `id_info` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `email_verification`
--
ALTER TABLE `email_verification`
  ADD CONSTRAINT `email_verification_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id_user`);

--
-- Filtros para la tabla `password_resets`
--
ALTER TABLE `password_resets`
  ADD CONSTRAINT `password_resets_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id_user`);

--
-- Filtros para la tabla `users`
--
ALTER TABLE `users`
  ADD CONSTRAINT `users_ibfk_1` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id_rol`);

--
-- Filtros para la tabla `user_information`
--
ALTER TABLE `user_information`
  ADD CONSTRAINT `user_information_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id_user`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
