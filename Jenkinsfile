// Ruoyu.Study - Identity Service Pipeline
//
// Per-service pipeline for QuantumZhou.Identity:
//   1. Preflight — verify docker + repo mount
//   2. Build    — reuse script/build-script/01-identity.build.sh (docker build)
//   3. UT       — run unit tests in a throwaway dotnet/sdk:8.0 container
//   4. Deploy   — restart the ruoyu-identity container via start.sh
//   5. Smoke    — health check + admin login
//
// The Jenkins controller runs inside Docker and drives the host Docker daemon
// via the bind-mounted /var/run/docker.sock. The repo is mounted read-only at
// /srv/repo by script/env-script/07-jenkins/start.sh.
//
// Build context = repo root (needed because the Dockerfile COPYs ruoyu.common).
// UT runs against the repo source via a throwaway `dotnet/sdk:8.0` container
// with the repo mounted at /src:ro and an output dir on the Jenkins workspace.

pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        REPO_DIR         = '/srv/repo'
        SERVICE_DIR      = "${env.REPO_DIR}/src/services/QuantumZhou.Identity"
        BUILD_SCRIPT     = "${env.REPO_DIR}/script/build-script/01-identity.build.sh"
        TEST_PROJ       = "${env.SERVICE_DIR}/backend/Tests/unit/QuantumZhou.Identity.Tests.csproj"
        START_SCRIPT     = "${env.SERVICE_DIR}/start.sh"
        REPORT_DIR       = "${env.WORKSPACE}/reports"
        // Use Aliyun NuGet mirror for faster restores inside China.
        NUGET_SOURCE     = 'https://nuget.cdn.azure.cn/v3/index.json'
    }

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
                    echo "=== Repo mount ==="
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
                    set +e
                    mkdir -p "$REPORT_DIR"
                    # Run UT in a throwaway sdk container against the read-only repo.
                    # Test results are written to the Jenkins workspace via a bind-mount.
                    docker run --rm \
                        -v "$REPO_DIR":/src:ro \
                        -v "$REPORT_DIR":/reports \
                        -w /src/src/services/QuantumZhou.Identity \
                        mcr.microsoft.com/dotnet/sdk:8.0 \
                        bash -c "
                            set -e
                            # Use Aliyun NuGet mirror for faster restores in China
                            dotnet nuget add source $NUGET_SOURCE -n AliyunMirror || true
                            dotnet test backend/Tests/unit/QuantumZhou.Identity.Tests.csproj \
                                --configuration Release \
                                --logger 'trx;logfilename=identity-ut.trx' \
                                --results-directory /reports \
                                --no-restore
                            echo 'UT completed'
                        " 2>&1 | tee "$REPORT_DIR/ut-console.log"
                    UT_EXIT=${PIPESTATUS[0]}
                    echo "UT exit code: $UT_EXIT"
                    exit $UT_EXIT
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
                    bash "$START_SCRIPT" &
                    START_PID=$!
                    # start.sh ends with `docker logs -f`, which blocks. Give it
                    # 15 seconds to spin up the container, then detach.
                    sleep 15
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
            junit testResults: 'reports/*.trx', allowEmptyResults: true
        }
        success {
            echo 'Identity pipeline PASSED: build + UT + deploy + smoke'
        }
        failure {
            echo 'Identity pipeline FAILED — check logs above'
        }
    }
}
