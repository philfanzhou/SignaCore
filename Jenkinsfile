// Ruoyu.Study - Identity Service Pipeline
//
// Per-service pipeline for QuantumZhou.Identity:
//   1. Preflight — verify docker + dotnet + repo access
//   2. Build    — reuse script/build-script/01-identity.build.sh (docker build)
//   3. UT       — run unit tests directly on host via dotnet SDK 8.0
//   4. Deploy   — restart the ruoyu-identity container via start.sh
//   5. Smoke    — health check + admin login
//
// Jenkins runs inside the ruoyu-jenkins:custom Docker container (see
// script/env-script/07-jenkins/). The repo is mounted read-only at /srv/repo.
// .NET 8 SDK is pre-installed in the custom image. Docker CLI reaches the host
// daemon via the bind-mounted /var/run/docker.sock.
//
// Build context = repo root (needed because the Dockerfile COPYs ruoyu.common).

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        REPO_DIR         = "${env.REPO_DIR ?: '/srv/repo'}"
        SERVICE_DIR      = "${env.REPO_DIR}/src/services/QuantumZhou.Identity"
        BUILD_SCRIPT     = "${env.REPO_DIR}/script/build-script/01-identity.build.sh"
        TEST_PROJ        = "${env.SERVICE_DIR}/backend/Tests/unit/QuantumZhou.Identity.Tests.csproj"
        INTEGRATION_PROJ = "${env.SERVICE_DIR}/backend/Tests/integration/QuantumZhou.Identity.IntegrationTests.csproj"
        START_SCRIPT     = "${env.SERVICE_DIR}/start.sh"
        REPORT_DIR       = "${env.WORKSPACE}/reports"
        // Use Huawei NuGet mirror for faster restores inside China.
        NUGET_SOURCE     = 'https://repo.huaweicloud.com/repository/nuget/v3/index.json'
        // Consul ACL token — required by start.sh to read shared PostgreSQL config
        // from Consul KV (config/ruoyu/shared.json). Provisioned in Jenkins credentials
        // as 'consul-acl-token' (Secret text). Value mirrors
        // script/env-script/06-consul/config/server.json (initial_management).
        CONSUL_TOKEN     = credentials('consul-acl-token')
    }

    triggers { pollSCM('H/5 * * * *') }

    stages {
        stage('Preflight') {
            steps {
                sh '''
                    set -e
                    echo "=== Jenkins user ==="
                    id
                    echo ""
                    echo "=== Docker access ==="
                    docker info --format 'Server Version: {{.ServerVersion}}'
                    echo ""
                    echo "=== dotnet SDK ==="
                    dotnet --version
                    echo ""
                    echo "=== Repo symlink ==="
                    ls -la "$REPO_DIR" | head -10
                    echo ""
                    echo "=== Identity source tree ==="
                    ls -la "$SERVICE_DIR/backend"
                    echo ""
                    echo "=== Build script ==="
                    ls -la "$BUILD_SCRIPT"
                    echo ""
                    echo "=== Test project ==="
                    ls -la "$TEST_PROJ"
                '''
            }
        }

        stage('Build Image') {
            steps {
                sh '''
                    set -e
                    cd "$REPO_DIR"
                    bash "$BUILD_SCRIPT"
                    docker images quantumzhou.identity --format '{{.Repository}}:{{.Tag}} {{.CreatedSince}} {{.Size}}'
                '''
            }
        }

        stage('Unit Test') {
            steps {
                sh '''
                    set -e
                    mkdir -p "$REPORT_DIR"
                    cd "$SERVICE_DIR"
                    # Clean ALL stale obj/bin under ruoyu.common and this service —
                    # a previous Docker build leaves incomplete project.assets.json
                    # (empty projectReferences -> CS0234) and missing ref DLLs
                    # (obj/Release/net8.0/ref/ empty -> CS0006) for every transitively
                    # restored project, not just Tests.
                    COMMON_DIR="$REPO_DIR/src/ruoyu.common"
                    find "$COMMON_DIR" -type d \\( -name obj -o -name bin \\) -prune -exec rm -rf {} + 2>/dev/null || true
                    find "$SERVICE_DIR" -type d \\( -name obj -o -name bin \\) -prune -exec rm -rf {} + 2>/dev/null || true
                    # Restore + test directly on host (no throwaway container needed).
                    dotnet restore backend/Tests/unit/QuantumZhou.Identity.Tests.csproj \
                        --source "$NUGET_SOURCE"
                    dotnet test backend/Tests/unit/QuantumZhou.Identity.Tests.csproj \
                        --configuration Release \
                        --logger 'trx;logfilename=identity-ut.trx' \
                        --results-directory "$REPORT_DIR" \
                        --no-restore
                    echo 'UT completed'
                '''
            }
        }

        stage('Database Contract Test') {
            steps {
                sh '''
                    set -e
                    mkdir -p "$REPORT_DIR"
                    cd "$SERVICE_DIR"
                    dotnet restore "$INTEGRATION_PROJ" \
                        --source "$NUGET_SOURCE"
                    RUN_IDENTITY_DATABASE_CONTRACTS=true \
                    TESTCONTAINERS_HOST_OVERRIDE=host.docker.internal \
                    dotnet test "$INTEGRATION_PROJ" \
                        --configuration Release \
                        --filter 'FullyQualifiedName~DatabaseContractTests' \
                        --logger 'trx;logfilename=identity-database-contracts.trx' \
                        --results-directory "$REPORT_DIR" \
                        --no-restore
                    echo 'Database contract matrix completed'
                '''
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    set -e
                    # start.sh stops+removes the old container, pulls latest image
                    # (already built locally), and starts a fresh one.
                    # It is the same script used for manual deployment.
                    cd "$SERVICE_DIR"
                    # start.sh ends with `docker logs -f`, which blocks. Give it
                    # 20 seconds to spin up the container, then detach.
                    bash "$START_SCRIPT" &
                    START_PID=$!
                    sleep 20
                    kill $START_PID 2>/dev/null || true
                    docker ps --filter 'name=ruoyu-identity' --format '{{.Names}} {{.Status}}'
                '''
            }
        }

        stage('Smoke Test') {
            steps {
                sh '''
                    set +e
                    # Wait for Identity to be ready (up to 30s)
                    for i in $(seq 1 30); do
                        CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 \
                            http://localhost:5002/.well-known/openid-configuration 2>/dev/null || echo 000)
                        if [ "$CODE" = "200" ]; then
                            echo "Identity ready after ${i}s"
                            break
                        fi
                        echo "Attempt $i: HTTP $CODE, retrying..."
                        sleep 1
                    done

                    echo "=== OIDC discovery ==="
                    curl -s --max-time 5 http://localhost:5002/.well-known/openid-configuration | head -c 300
                    echo ""

                    echo "=== Admin login ==="
                    LOGIN=$(curl -s -X POST http://localhost:5002/api/auth/token \
                        -H "Content-Type: application/json" \
                        -d '{"grantType":"password","username":"admin","password":"Qwer1234"}')
                    echo "Login response: $(echo "$LOGIN" | head -c 200)"
                    TOKEN=$(echo "$LOGIN" | python3 -c "import sys,json;print(json.load(sys.stdin).get('accessToken',''))" 2>/dev/null)

                    if [ -n "$TOKEN" ] && [ ${#TOKEN} -gt 500 ]; then
                        echo "Admin login OK, token length=${#TOKEN}"
                        exit 0
                    else
                        echo "Admin login FAILED"
                        exit 1
                    fi
                '''
            }
        }
    }

    post {
        always {
            echo "=== Collecting artifacts ==="
            script {
                sh '''
                    mkdir -p "$REPORT_DIR"
                    ls -la "$REPORT_DIR/" || true
                '''
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        success {
            echo 'Identity pipeline PASSED: build + UT + deploy + smoke'
        }
        failure {
            echo 'Identity pipeline FAILED — check logs above'
        }
    }
}
