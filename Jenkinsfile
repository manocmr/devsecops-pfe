pipeline {
    agent any

    tools {
        jdk 'JDK-21'
    }

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20'))
    }

    environment {
        APP_NAME              = "devsecops-pipeline-test"
        REGISTRY              = "registry.example.com"
        IMAGE_TAG             = "${env.BUILD_NUMBER}"
        IMAGE_FULL            = "${REGISTRY}/${APP_NAME}:${IMAGE_TAG}"

        PUSHGATEWAY_URL       = "http://pushgateway.monitoring.svc:9091"
        JOB_LABEL             = "jenkins_devsecops"

        STAGING_NAMESPACE     = "staging"
        PRODUCTION_NAMESPACE  = "production"
        K8S_DEPLOYMENT_NAME   = "devsecops-app"
        K8S_CONTAINER_NAME    = "app"

        SECURITY_POLICY_FILE  = "security-policy.json"

        // Valeurs par défaut, recalculées par la Policy Evaluation
        SECURITY_BLOCK_DEPLOY = "false"
        SECURITY_SCORE        = "100"

        // Suivi d'état du déploiement production (pour rollback ciblé)
        PRODUCTION_DEPLOYED   = "false"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Build App') {
            steps {
                script {
                    runStageWithMetric('build_app') {
                        bat 'mvn clean package -DskipTests'
                    }
                }
            }
        }

        stage('Terraform Validate') {
            when {
                expression { fileExists('terraform') }
            }
            steps {
                script {
                    runStageWithMetric('terraform_validate') {
                        dir('terraform') {
                            bat 'terraform init -backend=false'
                            bat 'terraform validate'
                        }
                    }
                }
            }
        }

        // ── IaC Scans ─────────────────────────────────────────────────────────
        // Les scans ne bloquent pas le pipeline : c'est la Policy Evaluation
        // qui décide. On force exit 0 pour que le stage reste vert même si
        // l'outil trouve des violations (comportement attendu).

        stage('IaC Scan - Checkov') {
            steps {
                script {
                    runStageWithMetric('iac_scan_checkov') {
                        bat 'checkov -d terraform --framework terraform -o json > checkov-terraform.json || exit 0'
                        bat 'checkov -d kubernetes --framework kubernetes -o json > checkov-kubernetes.json || exit 0'
                    }
                }
            }
        }

        stage('IaC Scan - Tfsec') {
            when {
                expression { fileExists('terraform') }
            }
            steps {
                script {
                    runStageWithMetric('iac_scan_tfsec') {
                        bat 'tfsec terraform --format json --out tfsec-report.json || exit 0'
                    }
                }
            }
        }

        stage('IaC Scan - Terrascan') {
            steps {
                script {
                    runStageWithMetric('iac_scan_terrascan') {
                        bat 'terrascan scan -i terraform -d terraform -o json > terrascan-terraform.json || exit 0'
                        bat 'terrascan scan -i k8s -d kubernetes -o json > terrascan-kubernetes.json || exit 0'
                    }
                }
            }
        }

        stage('IaC Scan - Trivy Config') {
            steps {
                script {
                    runStageWithMetric('iac_scan_trivy_config') {
                        bat 'trivy config terraform --format json --output trivy-terraform.json || exit 0'
                        bat 'trivy config kubernetes --format json --output trivy-kubernetes.json || exit 0'
                    }
                }
            }
        }

        stage('Validate Kubernetes YAML') {
            when {
                expression { fileExists('kubernetes') }
            }
            steps {
                script {
                    runStageWithMetric('validate_k8s_yaml') {
                        bat 'kubectl apply --dry-run=client -f kubernetes'
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    runStageWithMetric('build_docker_image') {
                        bat 'docker build -t %IMAGE_FULL% .'
                    }
                }
            }
        }

        stage('Docker Scan - Trivy Image') {
            steps {
                script {
                    runStageWithMetric('docker_scan_trivy_image') {
                        bat 'trivy image %IMAGE_FULL% --scanners vuln,misconfig,secret --format json --output trivy-image-report.json || exit 0'
                    }
                }
            }
        }

        stage('Security Policy Evaluation') {
            steps {
                script {
                    runStageWithMetric('security_policy_evaluation') {
                        powershell '''
$ErrorActionPreference = "Stop"

function Read-JsonFile {
    param([string]$Path)
    if (Test-Path $Path) {
        return Get-Content $Path -Raw | ConvertFrom-Json
    }
    return $null
}

$critical = 0
$high = 0
$medium = 0
$low = 0
$secrets = 0
$iacFailed = 0

# ---- Trivy image
$trivyImage = Read-JsonFile "trivy-image-report.json"
if ($trivyImage -and $trivyImage.Results) {
    foreach ($result in $trivyImage.Results) {
        if ($result.Vulnerabilities) {
            foreach ($v in $result.Vulnerabilities) {
                switch ($v.Severity) {
                    "CRITICAL" { $critical++ }
                    "HIGH"     { $high++ }
                    "MEDIUM"   { $medium++ }
                    "LOW"      { $low++ }
                }
            }
        }
        if ($result.Misconfigurations) {
            foreach ($m in $result.Misconfigurations) {
                switch ($m.Severity) {
                    "CRITICAL" { $critical++ }
                    "HIGH"     { $high++ }
                    "MEDIUM"   { $medium++ }
                    "LOW"      { $low++ }
                }
            }
        }
        if ($result.Secrets) {
            $secrets += @($result.Secrets).Count
        }
    }
}

# ---- Trivy config terraform / kubernetes
foreach ($file in @("trivy-terraform.json", "trivy-kubernetes.json")) {
    $trivyConfig = Read-JsonFile $file
    if ($trivyConfig -and $trivyConfig.Results) {
        foreach ($result in $trivyConfig.Results) {
            if ($result.Misconfigurations) {
                foreach ($m in $result.Misconfigurations) {
                    switch ($m.Severity) {
                        "CRITICAL" { $critical++ }
                        "HIGH"     { $high++ }
                        "MEDIUM"   { $medium++ }
                        "LOW"      { $low++ }
                    }
                }
            }
        }
    }
}

# ---- Checkov
foreach ($file in @("checkov-terraform.json", "checkov-kubernetes.json")) {
    $checkov = Read-JsonFile $file
    if ($checkov -and $checkov.summary -and $checkov.summary.failed) {
        $iacFailed += [int]$checkov.summary.failed
    }
}

# ---- Tfsec
$tfsec = Read-JsonFile "tfsec-report.json"
if ($tfsec -and $tfsec.results) {
    $iacFailed += @($tfsec.results).Count
}

# ---- Terrascan
foreach ($file in @("terrascan-terraform.json", "terrascan-kubernetes.json")) {
    $terrascan = Read-JsonFile $file
    if ($terrascan -and $terrascan.results -and $terrascan.results.violations) {
        $iacFailed += @($terrascan.results.violations).Count
    }
}

# ---- Policy
$block = $false

if ($secrets -gt 0) { $block = $true }
if ($critical -gt 0) { $block = $true }
if ($high -gt 5) { $block = $true }
if ($iacFailed -gt 10) { $block = $true }

# Score normalisé : pénalités plafonnées par catégorie pour éviter
# des valeurs aberrantes avec un grand nombre de findings.
$penaltyCritical = [Math]::Min($critical * 20, 60)
$penaltyHigh     = [Math]::Min($high * 5, 30)
$penaltySecrets  = [Math]::Min($secrets * 15, 30)
$score = [Math]::Max(0, 100 - $penaltyCritical - $penaltyHigh - $penaltySecrets)

@"
CRITICAL=$critical
HIGH=$high
MEDIUM=$medium
LOW=$low
SECRETS=$secrets
IAC_FAILED=$iacFailed
SECURITY_SCORE=$score
SECURITY_BLOCK_DEPLOY=$block
"@ | Out-File -FilePath security-summary.env -Encoding ascii

Write-Host "Security summary generated."
Write-Host "  CRITICAL=$critical  HIGH=$high  MEDIUM=$medium  LOW=$low"
Write-Host "  SECRETS=$secrets  IAC_FAILED=$iacFailed"
Write-Host "  SCORE=$score  BLOCK_DEPLOY=$block"
'''
                    }
                }
            }
        }

        stage('Load Security Decision') {
            steps {
                script {
                    def props = readProperties file: 'security-summary.env'

                    env.CRITICAL_FINDINGS     = props['CRITICAL'] ?: '0'
                    env.HIGH_FINDINGS         = props['HIGH'] ?: '0'
                    env.MEDIUM_FINDINGS       = props['MEDIUM'] ?: '0'
                    env.LOW_FINDINGS          = props['LOW'] ?: '0'
                    env.SECRETS_FOUND         = props['SECRETS'] ?: '0'
                    env.IAC_FAILED            = props['IAC_FAILED'] ?: '0'
                    env.SECURITY_SCORE        = props['SECURITY_SCORE'] ?: '0'
                    env.SECURITY_BLOCK_DEPLOY = props['SECURITY_BLOCK_DEPLOY'] ?: 'true'

                    echo "═══ Security Gate ════════════════════════"
                    echo "CRITICAL : ${env.CRITICAL_FINDINGS}"
                    echo "HIGH     : ${env.HIGH_FINDINGS}"
                    echo "MEDIUM   : ${env.MEDIUM_FINDINGS}"
                    echo "LOW      : ${env.LOW_FINDINGS}"
                    echo "SECRETS  : ${env.SECRETS_FOUND}"
                    echo "IAC_FAIL : ${env.IAC_FAILED}"
                    echo "SCORE    : ${env.SECURITY_SCORE}"
                    echo "BLOCKED  : ${env.SECURITY_BLOCK_DEPLOY}"
                    echo "══════════════════════════════════════════"
                }
            }
        }

        stage('Push Docker Image') {
            when {
                expression { env.SECURITY_BLOCK_DEPLOY != 'true' }
            }
            steps {
                script {
                    runStageWithMetric('push_docker_image') {
                        withCredentials([usernamePassword(credentialsId: 'registry-creds', usernameVariable: 'REG_USER', passwordVariable: 'REG_PASS')]) {
                            bat 'docker login %REGISTRY% -u %REG_USER% -p %REG_PASS%'
                            bat 'docker push %IMAGE_FULL%'
                        }
                    }
                }
            }
        }

        stage('Deploy Staging') {
            when {
                expression { env.SECURITY_BLOCK_DEPLOY != 'true' }
            }
            steps {
                script {
                    runStageWithMetric('deploy_staging') {
                        withCredentials([file(credentialsId: 'kubeconfig-staging', variable: 'KUBECONFIG')]) {
                            bat 'kubectl set image deployment/%K8S_DEPLOYMENT_NAME% %K8S_CONTAINER_NAME%=%IMAGE_FULL% -n %STAGING_NAMESPACE%'
                            bat 'kubectl rollout status deployment/%K8S_DEPLOYMENT_NAME% -n %STAGING_NAMESPACE% --timeout=180s'
                        }
                    }
                }
            }
        }

        stage('Smoke Tests Staging') {
            when {
                expression { env.SECURITY_BLOCK_DEPLOY != 'true' }
            }
            steps {
                script {
                    runStageWithMetric('smoke_tests_staging') {
                        echo 'Executer ici les smoke tests de staging'
                        // TODO: ajouter curl / newman / pytest smoke tests
                    }
                }
            }
        }

        stage('Approval Production') {
            when {
                expression { env.SECURITY_BLOCK_DEPLOY != 'true' }
            }
            steps {
                timeout(time: 10, unit: 'MINUTES') {
                    input message: "Déployer ${env.IMAGE_FULL} en production ?"
                }
            }
        }

        stage('Deploy Production') {
            when {
                expression { env.SECURITY_BLOCK_DEPLOY != 'true' }
            }
            steps {
                script {
                    runStageWithMetric('deploy_production') {
                        withCredentials([file(credentialsId: 'kubeconfig-prod', variable: 'KUBECONFIG')]) {
                            bat 'kubectl set image deployment/%K8S_DEPLOYMENT_NAME% %K8S_CONTAINER_NAME%=%IMAGE_FULL% -n %PRODUCTION_NAMESPACE%'
                            bat 'kubectl rollout status deployment/%K8S_DEPLOYMENT_NAME% -n %PRODUCTION_NAMESPACE% --timeout=180s'
                        }
                    }
                    // Marquer le déploiement production comme effectué
                    // pour activer le rollback ciblé en cas d'échec ultérieur.
                    env.PRODUCTION_DEPLOYED = 'true'
                }
            }
        }
    }

    post {
        always {
            // FIX: suppression de l'espace après la virgule dans le glob
            archiveArtifacts artifacts: '*.json,security-summary.env', allowEmptyArchive: true

            script {
                // ── Accumulation de toutes les métriques dans un seul .prom ──
                // puis push groupé vers le Pushgateway (1 seul POST).
                // Avantage : les labels précédents ne sont pas écrasés
                // partiellement si une métrique individuelle échoue.

                def lines = []

                // Helper local pour ajouter une ligne au buffer
                def addLine = { String metricName, String stageName, def value, Map extraLabels = [:] ->
                    def safeJob   = (env.JOB_NAME ?: 'unknown').replaceAll('[^a-zA-Z0-9_-]', '_')
                    def safeStage = (stageName ?: 'unknown').replaceAll('[^a-zA-Z0-9_-]', '_')
                    def labels    = [job: safeJob, stage: safeStage, build: env.BUILD_NUMBER] + extraLabels
                    def labelStr  = labels.collect { k, v -> "${k}=\"${v.toString().replaceAll('"', '\\"')}\"" }.join(',')
                    lines << "${metricName}{${labelStr}} ${value}"
                }

                // Build global
                addLine('jenkins_build_result',           'global', currentBuild.currentResult == 'SUCCESS' ? 0 : 1)
                addLine('jenkins_build_duration_seconds', 'global', (currentBuild.duration / 1000) as long)

                // Security findings
                addLine('security_findings_total', 'critical', env.CRITICAL_FINDINGS ?: '0', [severity: 'CRITICAL', tool: 'global'])
                addLine('security_findings_total', 'high',     env.HIGH_FINDINGS     ?: '0', [severity: 'HIGH',     tool: 'global'])
                addLine('security_findings_total', 'medium',   env.MEDIUM_FINDINGS   ?: '0', [severity: 'MEDIUM',   tool: 'global'])
                addLine('security_findings_total', 'low',      env.LOW_FINDINGS      ?: '0', [severity: 'LOW',      tool: 'global'])
                addLine('security_secrets_found',    'global', env.SECRETS_FOUND     ?: '0', [scope: 'global'])
                addLine('security_iac_failed_total', 'global', env.IAC_FAILED        ?: '0', [scope: 'global'])
                addLine('security_compliance_score', 'global', env.SECURITY_SCORE    ?: '0', [scope: 'global'])
                addLine('deployment_blocked',        'global', (env.SECURITY_BLOCK_DEPLOY == 'true' ? 1 : 0), [scope: 'global'])

                // Générer le fichier .prom avec HELP/TYPE pour Prometheus
                def promLines = []
                promLines << "# HELP jenkins_build_result 0=SUCCESS 1=FAILURE"
                promLines << "# TYPE jenkins_build_result gauge"
                promLines << "# HELP jenkins_build_duration_seconds Durée du build en secondes"
                promLines << "# TYPE jenkins_build_duration_seconds gauge"
                promLines << "# HELP security_findings_total Findings sécurité par sévérité"
                promLines << "# TYPE security_findings_total gauge"
                promLines << "# HELP security_secrets_found Secrets détectés dans le code/image"
                promLines << "# TYPE security_secrets_found gauge"
                promLines << "# HELP security_iac_failed_total Règles IaC en échec"
                promLines << "# TYPE security_iac_failed_total gauge"
                promLines << "# HELP security_compliance_score Score de conformité sécurité (0-100)"
                promLines << "# TYPE security_compliance_score gauge"
                promLines << "# HELP deployment_blocked 1 si le déploiement a été bloqué par la security gate"
                promLines << "# TYPE deployment_blocked gauge"
                promLines += lines
                promLines << "" // ligne vide finale requise par le format Prometheus

                writeFile file: 'metrics.prom', text: promLines.join('\n')

                // Push groupé — un seul appel HTTP
                def safeJobName = (env.JOB_NAME ?: 'unknown').replaceAll('[^a-zA-Z0-9_-]', '_')
                def pushUrl = "${env.PUSHGATEWAY_URL}/metrics/job/${env.JOB_LABEL}/instance/${safeJobName}"

                powershell returnStatus: true, script: """
\$payload = Get-Content -Path 'metrics.prom' -Raw
try {
    Invoke-RestMethod -Uri '${pushUrl}' -Method PUT -Body \$payload -ContentType 'text/plain; version=0.0.4'
    Write-Host "Metrics pushed to Pushgateway: ${pushUrl}"
    exit 0
}
catch {
    Write-Host "WARNING: Pushgateway push failed - \$(\$_.Exception.Message)"
    exit 0
}
"""
                // Archiver aussi le fichier .prom pour debug
                archiveArtifacts artifacts: 'metrics.prom', allowEmptyArchive: true
            }
        }

        success {
            echo 'SUCCESS — pipeline DevSecOps conforme'
        }

        failure {
            echo 'ECHEC — pipeline bloqué'
            script {
                // FIX: rollback uniquement si le déploiement production
                // a effectivement eu lieu (PRODUCTION_DEPLOYED=true).
                // Avant le fix, la condition était inversée et pouvait tenter
                // un rollback même quand rien n'avait été déployé.
                if (env.PRODUCTION_DEPLOYED == 'true') {
                    echo "Rollback production déclenché pour ${env.K8S_DEPLOYMENT_NAME}"
                    withCredentials([file(credentialsId: 'kubeconfig-prod', variable: 'KUBECONFIG')]) {
                        powershell returnStatus: true, script: '''
try {
    kubectl rollout undo deployment/%K8S_DEPLOYMENT_NAME% -n %PRODUCTION_NAMESPACE%
    Write-Host "Rollback production executé."
}
catch {
    Write-Host "Rollback production échoué ou non nécessaire : $($_.Exception.Message)"
}
'''
                    }
                } else {
                    echo "Aucun déploiement production détecté — rollback ignoré."
                }
            }
        }

        unstable {
            echo 'INSTABLE — vérifier les rapports de sécurité'
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Exécute un bloc et pousse automatiquement les métriques de durée/statut
 * du stage vers le buffer global (via pushMetric).
 */
def runStageWithMetric(String metricStageName, Closure body) {
    def status = 0
    def start  = System.currentTimeMillis()

    try {
        body()
    } catch (e) {
        status = 1
        throw e
    } finally {
        def durationSeconds = ((System.currentTimeMillis() - start) / 1000) as long
        pushMetric('jenkins_stage_status',           metricStageName, status)
        pushMetric('jenkins_stage_duration_seconds', metricStageName, durationSeconds)
    }
}

/**
 * Push immédiat d'une métrique individuelle vers le Pushgateway.
 * Utilisé par runStageWithMetric() pour les métriques de stage en temps réel.
 * Pour les métriques globales du post{}, préférer le push groupé via metrics.prom.
 */
def pushMetric(String metricName, String stageName, def value, Map extraLabels = [:]) {
    def safeJobName   = (env.JOB_NAME ?: 'unknown_job').replaceAll('[^a-zA-Z0-9_-]', '_')
    def safeStageName = (stageName ?: 'unknown_stage').replaceAll('[^a-zA-Z0-9_-]', '_')

    def labels = [
        job  : safeJobName,
        stage: safeStageName,
        build: env.BUILD_NUMBER ?: '0'
    ] + extraLabels

    def labelString = labels.collect { k, v ->
        "${k}=\"${v.toString().replaceAll('"', '\\"')}\""
    }.join(',')

    def payload = "# TYPE ${metricName} gauge\n${metricName}{${labelString}} ${value}\n"
    def url     = "${env.PUSHGATEWAY_URL}/metrics/job/${env.JOB_LABEL}/instance/${safeJobName}"

    powershell returnStatus: true, script: """
\$body = @'
${payload}
'@

try {
    Invoke-RestMethod -Uri '${url}' -Method POST -Body \$body -ContentType 'text/plain; version=0.0.4'
    exit 0
}
catch {
    Write-Host "WARNING metric push failed: \$(\$_.Exception.Message)"
    exit 0
}
"""
}
