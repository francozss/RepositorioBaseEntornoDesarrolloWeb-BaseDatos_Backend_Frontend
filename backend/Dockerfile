FROM node:22-bookworm-slim

WORKDIR /app

# Instalar dependencias de forma limpia y reproducible
COPY package*.json ./
RUN npm install

# Copiar código fuente y asignar permisos al usuario no-root 'node'
COPY . .
RUN chown -R node:node /app

USER node
EXPOSE 4000

CMD ["npm", "run", "dev"]
