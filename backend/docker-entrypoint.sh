#!/bin/sh
set -e

# Apply DB migrations before starting (schema owned by Alembic in production).
echo "Running database migrations..."
alembic upgrade head

echo "Starting: $@"
exec "$@"
