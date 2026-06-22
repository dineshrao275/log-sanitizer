# Use official PHP 8.2 CLI image
FROM php:8.2-cli

# Install system dependencies & useful extensions
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    zip \
    && docker-php-ext-install opcache \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Composer globally (official way)
COPY --from=composer:2.7 /usr/bin/composer /usr/bin/composer

# Set working directory inside container
WORKDIR /app

# Copy everything from your local folder into container
COPY . .

# Install PHP dependencies
RUN composer install --no-interaction --prefer-dist