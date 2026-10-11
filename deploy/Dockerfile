# syntax=docker/dockerfile:1.7
# One build definition for every application image. PROJECT selects the project to publish, e.g. Halka.Iam.
# No secret, key or certificate is copied into any layer: .dockerignore excludes .local and all key formats, and
# runtime material is mounted by Compose.

ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0.401
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0.12

FROM ${SDK_IMAGE} AS build
ARG PROJECT
WORKDIR /src
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1

COPY global.json nuget.config Directory.Build.props Directory.Packages.props ./
COPY src/ src/
RUN dotnet restore "src/${PROJECT}/${PROJECT}.csproj" --locked-mode
RUN dotnet publish "src/${PROJECT}/${PROJECT}.csproj" -c Release --no-restore -o /app -p:UseAppHost=false -p:DebugType=none

FROM ${RUNTIME_IMAGE} AS final
WORKDIR /app
ENV DOTNET_NOLOGO=1 \
    DOTNET_CLI_TELEMETRY_OPTOUT=1 \
    DOTNET_EnableDiagnostics=0 \
    ASPNETCORE_ENVIRONMENT=Production
COPY --from=build /app .
# Non-root user shipped with the .NET runtime images (UID 1654).
USER $APP_UID
ENTRYPOINT ["dotnet"]
