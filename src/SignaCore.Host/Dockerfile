# No `syntax` directive: it would make every build pull the frontend image from Docker Hub, which
# meters anonymous pulls per client address. Nothing here needs a feature beyond the frontend that
# BuildKit already ships. Re-add the directive if that changes, and expect the Docker Hub pull back.

# Default local builds retain the official multi-platform AWS mirror tag. CI supplies a verified
# official Linux/amd64 digest through NODE_IMAGE; both anonymous registries have quotas.
ARG NODE_IMAGE=public.ecr.aws/docker/library/node:24-alpine
FROM ${NODE_IMAGE} AS frontend-build
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
# Targeted upgrade of the Ubuntu openssl source packages (openssl, libssl3t64) to clear
# CVE-2026-84782 from the floating aspnet tag. Only these two packages are upgraded; once the
# base image ships the fixed version this step becomes a no-op, and the CI Trivy gate stays as
# the independent guard against image regressions.
RUN apt-get update && \
    apt-get install -y --no-install-recommends --only-upgrade openssl libssl3t64 && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /app
LABEL org.opencontainers.image.title="SignaCore" \
      org.opencontainers.image.description="Identity and authentication service" \
      org.opencontainers.image.source="https://github.com/philfanzhou/SignaCore"
COPY --from=backend-build --chown=app:app /app/publish .
# /app/config is the writable persistent bootstrap directory:
#   /app/config/signacore.bootstrap.json
# The service creates or atomically replaces the file after protected setup. It holds only the
# database connection and the external root key. /app/data remains available for mutable runtime
# data but is not a configuration authority.
RUN mkdir -p /app/data /app/config && chown -R app:app /app/data /app/config

EXPOSE 5002

USER $APP_UID
ENTRYPOINT ["dotnet", "SignaCore.Host.dll"]
