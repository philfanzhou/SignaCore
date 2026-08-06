# syntax=docker/dockerfile:1

# Build the administrative frontend.
FROM node:25-alpine AS frontend-build
ARG NPM_REGISTRY=https://registry.npmjs.org/
ENV npm_config_registry=${NPM_REGISTRY}
WORKDIR /app
COPY src/SignaCore.Admin/package*.json ./
RUN npm ci --registry=${NPM_REGISTRY}
COPY src/SignaCore.Admin/ ./
RUN npm run build

# Restore and publish the ASP.NET Core host.
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS backend-build
ARG BUILD_CONFIGURATION=Release
WORKDIR /workspace

# Copy dependency manifests first to preserve the restore cache.
COPY global.json Directory.Build.props Directory.Packages.props ./
COPY src/SignaCore.Database/SignaCore.Database.csproj src/SignaCore.Database/
COPY src/SignaCore.Database.Migrations.MySql/SignaCore.Database.Migrations.MySql.csproj src/SignaCore.Database.Migrations.MySql/
COPY src/SignaCore.Database.Migrations.Sqlite/SignaCore.Database.Migrations.Sqlite.csproj src/SignaCore.Database.Migrations.Sqlite/
COPY src/SignaCore.Domain/SignaCore.Domain.csproj src/SignaCore.Domain/
COPY src/SignaCore.Host/SignaCore.Host.csproj src/SignaCore.Host/
RUN dotnet restore "src/SignaCore.Host/SignaCore.Host.csproj"

# Copy source code and publish.
COPY src/ src/
COPY --from=frontend-build /app/dist src/SignaCore.Host/wwwroot
RUN dotnet publish "src/SignaCore.Host/SignaCore.Host.csproj" -c $BUILD_CONFIGURATION -o /app/publish --no-restore /p:UseAppHost=false

# Run with the non-root user provided by the official ASP.NET image.
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app
LABEL org.opencontainers.image.title="SignaCore" \
      org.opencontainers.image.description="Identity and authentication service" \
      org.opencontainers.image.source="https://github.com/philfanzhou/SignaCore"
COPY --from=backend-build --chown=app:app /app/publish .
RUN mkdir -p /app/data && chown -R app:app /app/data

EXPOSE 5002

USER $APP_UID
ENTRYPOINT ["dotnet", "SignaCore.Host.dll"]
