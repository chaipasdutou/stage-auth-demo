FROM php:8.2-fpm-alpine AS builder

RUN apk add --no-cache \
    git \
    curl \
    postgresql-dev \
    && docker-php-ext-install pdo pdo_pgsql

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

WORKDIR /app

COPY composer.json composer.lock* ./

#install PHP dependencies
RUN composer install --no-dev --no-scripts --optimize-autoloader

FROM php:8.2-fpm-alpine

RUN apk add --no-cache \
    postgresql-client \
    libpq

# Copy PHP extensions from builder
COPY --from=builder /usr/local/lib/php/extensions /usr/local/lib/php/extensions
COPY --from=builder /usr/local/etc/php/conf.d /usr/local/etc/php/conf.d

# Enable extensions
RUN docker-php-ext-enable pdo_pgsql

#cpy PHP configuration
RUN echo "memory_limit = 256M" >> /usr/local/etc/php/conf.d/custom.ini

WORKDIR /app

#copy application from builder
COPY --from=builder /app/vendor /app/vendor
COPY . .

RUN mkdir -p var/cache var/log && chmod -R 777 var/

EXPOSE 9000

CMD ["php-fpm"]
