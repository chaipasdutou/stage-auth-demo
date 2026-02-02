#!/bin/bash

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Stage Auth Demo - Docker Setup ===${NC}\n"

# Start containers
echo -e "${BLUE}Démarrage des conteneurs Docker...${NC}"
docker compose up -d

# Wait for database
echo -e "${BLUE}Attente du démarrage de la base de données...${NC}"
sleep 5

# Run migrations
echo -e "${BLUE}Exécution des migrations...${NC}"
docker compose exec -T app php bin/console doctrine:migrations:migrate --no-interaction

# Create database if needed
docker compose exec -T app php bin/console doctrine:database:create --if-not-exists 2>/dev/null || true

echo -e "${GREEN}✓ Démarrage terminé!${NC}"
echo -e "${GREEN}L'application est disponible sur http://localhost:8000${NC}\n"

echo -e "${BLUE}Commandes utiles:${NC}"
echo "  - docker compose logs -f              : Afficher les logs"
echo "  - docker compose down                 : Arrêter les conteneurs"
echo "  - docker compose exec app bash        : Accéder au shell du conteneur"
echo "  - docker compose exec app php bin/console : Commandes Symfony"
