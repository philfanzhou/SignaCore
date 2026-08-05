# ========== Stage 1: Build Frontend ==========
FROM node:20-alpine AS frontend-build
ARG NPM_REGISTRY=https://mirrors.huaweicloud.com/repository/npm/
ENV npm_config_registry=${NPM_REGISTRY}
ENV npm_config_replace_registry_host=always
WORKDIR /app
COPY admin_frontend/package*.json ./
RUN npm ci --registry=${NPM_REGISTRY}
COPY admin_frontend/ ./
RUN npm run build

# ========== Stage 2: Build & Publish Backend ==========
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS backend-build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy csproj files first for layer cache optimization
COPY backend/Database/QuantumZhou.Identity.Database.csproj backend/Database/
COPY backend/Database.Migrations.MySql/QuantumZhou.Identity.Database.Migrations.MySql.csproj backend/Database.Migrations.MySql/
COPY backend/Database.Migrations.Sqlite/QuantumZhou.Identity.Database.Migrations.Sqlite.csproj backend/Database.Migrations.Sqlite/
COPY backend/Domain/QuantumZhou.Identity.Domain.csproj backend/Domain/
COPY backend/Service/QuantumZhou.Identity.Service.csproj backend/Service/
COPY backend/Host/QuantumZhou.Identity.Host.csproj backend/Host/
RUN dotnet restore "backend/Host/QuantumZhou.Identity.Host.csproj"

# Copy source code and publish
COPY backend/ backend/
COPY --from=frontend-build /app/dist backend/Host/wwwroot
RUN dotnet publish "backend/Host/QuantumZhou.Identity.Host.csproj" -c $BUILD_CONFIGURATION -o /app/publish --no-restore /p:UseAppHost=false

# ========== Stage 3: Runtime ==========
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
COPY --from=backend-build /app/publish .

EXPOSE 5002

ENTRYPOINT ["dotnet", "QuantumZhou.Identity.Host.dll"]
