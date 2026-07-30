# ========== Stage 1: Build Frontend ==========
FROM node:20-alpine AS frontend-build
ARG NPM_REGISTRY=https://mirrors.huaweicloud.com/repository/npm/
ENV npm_config_registry=${NPM_REGISTRY}
ENV npm_config_replace_registry_host=always
WORKDIR /app
COPY src/services/QuantumZhou.Identity/admin_frontend/package*.json ./
RUN npm ci --registry=${NPM_REGISTRY}
COPY src/services/QuantumZhou.Identity/admin_frontend/ ./
RUN npm run build

# ========== Stage 2: Build & Publish Backend ==========
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS backend-build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src

# Copy csproj files first for layer cache optimization
COPY src/services/QuantumZhou.Identity/backend/Database/QuantumZhou.Identity.Database.csproj src/services/QuantumZhou.Identity/backend/Database/
COPY src/services/QuantumZhou.Identity/backend/Database.Migrations.MySql/QuantumZhou.Identity.Database.Migrations.MySql.csproj src/services/QuantumZhou.Identity/backend/Database.Migrations.MySql/
COPY src/services/QuantumZhou.Identity/backend/Database.Migrations.Sqlite/QuantumZhou.Identity.Database.Migrations.Sqlite.csproj src/services/QuantumZhou.Identity/backend/Database.Migrations.Sqlite/
COPY src/services/QuantumZhou.Identity/backend/Domain/QuantumZhou.Identity.Domain.csproj src/services/QuantumZhou.Identity/backend/Domain/
COPY src/services/QuantumZhou.Identity/backend/Service/QuantumZhou.Identity.Service.csproj src/services/QuantumZhou.Identity/backend/Service/
COPY src/services/QuantumZhou.Identity/backend/Host/QuantumZhou.Identity.Host.csproj src/services/QuantumZhou.Identity/backend/Host/
RUN dotnet restore "src/services/QuantumZhou.Identity/backend/Host/QuantumZhou.Identity.Host.csproj"

# Copy source code and publish
COPY src/services/QuantumZhou.Identity/ src/services/QuantumZhou.Identity/
COPY --from=frontend-build /app/dist src/services/QuantumZhou.Identity/backend/Host/wwwroot
RUN dotnet publish "src/services/QuantumZhou.Identity/backend/Host/QuantumZhou.Identity.Host.csproj" -c $BUILD_CONFIGURATION -o /app/publish --no-restore /p:UseAppHost=false

# ========== Stage 3: Runtime ==========
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=backend-build /app/publish .

EXPOSE 5002

ENTRYPOINT ["dotnet", "QuantumZhou.Identity.Host.dll"]
