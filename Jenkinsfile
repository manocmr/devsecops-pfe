pipeline {

    agent any



    parameters {

        string(name: 'CVSS_THRESHOLD', defaultValue: '7.0', description: 'Seuil CVSS : toute vulnérabilité avec un score max (NVD/RedHat/GHSA, etc.) >= cette valeur bloque le gate.')

        booleanParam(name: 'ENFORCE_NETPOL', defaultValue: false, description: 'Si coché : échec si aucune NetworkPolicy dans le namespace prod (après déploiement).')

        booleanParam(name: 'AGGRESSIVE_REMEDIATE', defaultValue: false, description: 'Si coché en échec : supprime le Deployment cible en prod (en plus du rollback).')

    }



    environment {

        JAVA_HOME       = credentials('java-home-cred')

        // Secret file Jenkins : le fichier kubeconfig est copié sur l'agent ; la variable reçoit le chemin temporaire.
        KUBECONFIG      = credentials('kubeconfig')



        APP_NAME             = "devsecops-app"

        IMAGE_NAME           = "${env.APP_NAME}:${env.BUILD_NUMBER}"

        K8S_DEPLOYMENT_NAME  = "secure-app"



        PRODUCT_TYPE    = "Jenkins"

    }



    stages {

        stage('Checkout') {

            steps {

                checkout scm

            }

        }



        stage('1. Build App & Docker Image') {

            steps {

                bat 'mvn clean package -DskipTests'

                bat "docker build -t ${env.IMAGE_NAME} ."

            }

        }



        stage('1.5 Scan de Secrets (Trivy)') {

            steps {

                catchError(buildResult: 'FAILURE') {

                    bat 'trivy fs --format json --output trivy-secrets.json --exit-code 1 --scanners secret .'

                }

            }

        }



        stage('2. Analyse IaC (Scan JSON natif)') {

            failFast false

            parallel {

                stage('Validation Templates') {

                    steps {

                        script {

                            if (fileExists('terraform')) {

                                catchError(buildResult: 'FAILURE') {

                                    dir('terraform') {

                                        bat 'terraform init -backend=false'

                                        bat 'terraform validate'

                                    }

                                }

                            }

                            if (fileExists('kubernetes')) {

                                catchError(buildResult: 'FAILURE') {

                                    bat 'kubectl apply --dry-run=client --validate=true -f kubernetes'

                                }

                            }

                        }

                    }

                }

                stage('Checkov Terraform') {

                    steps {

                        script {

                            if (fileExists('terraform')) {

                                catchError(buildResult: 'FAILURE') {

                                    bat 'checkov -d terraform --framework terraform -o json > checkov-terraform.json'

                                }

                            }

                        }

                    }

                }

                stage('Checkov Kubernetes') {

                    steps {

                        script {

                            if (fileExists('kubernetes')) {

                                catchError(buildResult: 'FAILURE') {

                                    bat 'checkov -d kubernetes --framework kubernetes -o json > checkov-kubernetes.json'

                                }

                            }

                        }

                    }

                }

                stage('Tfsec') {

                    when { expression { fileExists('terraform') } }

                    steps {

                        catchError(buildResult: 'FAILURE') {

                            bat 'tfsec terraform --format json --out tfsec-report.json'

                        }

                    }

                }

                stage('Terrascan') {

                    steps {

                        script {

                            if (fileExists('terraform')) {

                                catchError(buildResult: 'FAILURE') {

                                    bat 'terrascan scan -i terraform -d terraform -o json > terrascan-terraform.json'

                                }

                            }

                        }

                    }

                }

            }

        }



        stage('2.5 Sealed Secrets & Vault (optionnel)') {

            failFast false

            parallel {

                stage('Sealed Secrets (dry-run client)') {

                    steps {

                        script {

                            if (fileExists('kubernetes/sealed-secret-demo.yaml')) {

                                catchError(buildResult: 'UNSTABLE') {

                                    bat 'kubectl apply --dry-run=client -f kubernetes/sealed-secret-demo.yaml'

                                }

                            } else {

                                echo 'Aucun sealed-secret-demo.yaml : étape ignorée.'

                            }

                        }

                    }

                }

                stage('Vault (si VAULT_ADDR défini)') {

                    when {

                        expression { return env.VAULT_ADDR != null && !env.VAULT_ADDR.trim().isEmpty() }

                    }

                    steps {

                        withCredentials([string(credentialsId: 'vault-token', variable: 'VAULT_TOKEN')]) {

                            catchError(buildResult: 'FAILURE') {

                                bat '''

                                    vault.exe version

                                    vault.exe status

                                '''

                            }

                        }

                    }

                }

            }

        }



        stage('3. Scan Docker Image (Trivy JSON)') {

            steps {

                catchError(buildResult: 'FAILURE') {

                    bat "trivy image --format json --output trivy-report.json --exit-code 1 --severity HIGH,CRITICAL --scanners vuln,misconfig,secret ${env.IMAGE_NAME}"

                }

            }

        }



        stage('4. Sécurité Kubernetes') {

            steps {

                script {

                    catchError(buildResult: 'FAILURE') {

                        bat 'kubectl delete job kube-bench --ignore-not-found=true'

                        bat 'kubectl apply -f kubernetes/jobs/kube-bench-job.yaml'

                        bat 'kubectl wait --for=condition=complete job/kube-bench --timeout=180s'

                        bat 'kubectl logs job/kube-bench > kube-bench.json'

                        bat 'kubectl delete job kube-bench --ignore-not-found=true'

                    }

                    catchError(buildResult: 'FAILURE') {

                        bat 'kubectl delete job kube-hunter --ignore-not-found=true'

                        bat 'kubectl apply -f kubernetes/jobs/kube-hunter-job.yaml'

                        bat 'kubectl wait --for=condition=complete job/kube-hunter --timeout=180s'

                        bat 'kubectl logs job/kube-hunter > kube-hunter.json'

                        bat 'kubectl delete job kube-hunter --ignore-not-found=true'

                    }

                }

            }

        }



        stage('4.5 Audit RBAC & Network Policies') {

            steps {

                script {

                    catchError(buildResult: 'FAILURE') {

                        bat """

                            kubectl create namespace dev --dry-run=client -o yaml | kubectl apply -f -

                            kubectl create namespace staging --dry-run=client -o yaml | kubectl apply -f -

                            kubectl create namespace prod --dry-run=client -o yaml | kubectl apply -f -

                            kubectl get rolebindings,roles,clusterrolebindings -n dev -o wide > rbac-audit-dev.txt 2>&1

                            kubectl get rolebindings,roles,clusterrolebindings -n staging -o wide > rbac-audit-staging.txt 2>&1

                            kubectl get rolebindings,roles,clusterrolebindings -n prod -o wide > rbac-audit-prod.txt 2>&1

                            kubectl get networkpolicies.networking.k8s.io -A -o wide > netpol-audit-all.txt 2>&1

                        """

                    }

                    echo 'Rapports : rbac-audit-*.txt, netpol-audit-all.txt (archiver en artefact Jenkins si besoin).'

                }

            }

        }



        stage('5. Security Gate') {

            steps {

                script {

                    echo "Vérification des rapports (sévérité HIGH/CRITICAL, seuil CVSS, secrets)..."

                    def cvssMinStr = (params.CVSS_THRESHOLD ?: '7.0').toString().trim()

                    def highCritCount = 0

                    def cvssGateCount = 0

                    def secretCount = 0



                    if (fileExists('trivy-report.json')) {

                        def out = powershell(script: "\$CvssMin = [double]'${cvssMinStr}'; " + '''

$data = Get-Content -Raw trivy-report.json | ConvertFrom-Json

$sev = 0

$cvss = 0

if ($null -ne $data -and $null -ne $data.Results) {

    foreach ($res in $data.Results) {

        if ($null -eq $res.Vulnerabilities) { continue }

        foreach ($v in $res.Vulnerabilities) {

            if ($v.Severity -eq 'HIGH' -or $v.Severity -eq 'CRITICAL') { $sev++ }

            $maxScore = 0.0

            if ($null -ne $v.CVSS) {

                foreach ($p in $v.CVSS.PSObject.Properties) {

                    $o = $p.Value

                    if ($null -ne $o.V3Score -and [double]$o.V3Score -gt $maxScore) { $maxScore = [double]$o.V3Score }

                    if ($null -ne $o.V2Score -and [double]$o.V2Score -gt $maxScore) { $maxScore = [double]$o.V2Score }

                }

            }

            if ($maxScore -ge $CvssMin) { $cvss++ }

        }

    }

}

Write-Output $sev

Write-Output $cvss

''', returnStdout: true).trim()



                        def lines = out.split('\r?\n').findAll { it.matches("^\\d+\$") }

                        if (lines.size() >= 2) {

                            highCritCount = lines[0].toInteger()

                            cvssGateCount = lines[1].toInteger()

                        } else if (lines.size() == 1) {

                            highCritCount = lines[0].toInteger()

                        }

                    }



                    if (fileExists('trivy-secrets.json')) {

                        def out = powershell(script: '''

                            $data = Get-Content -Raw trivy-secrets.json | ConvertFrom-Json

                            $count = 0

                            if ($null -ne $data -and $null -ne $data.Results) {

                                foreach ($res in $data.Results) {

                                    if ($null -ne $res.Secrets) {

                                        $count += $res.Secrets.count

                                    }

                                }

                            }

                            Write-Output $count

                        ''', returnStdout: true).trim()



                        def lines = out.split('\r?\n')

                        for (def i = 0; i < lines.length; i++) {

                            if (lines[i].matches("^\\d+\$")) {

                                secretCount = lines[i].toInteger()

                            }

                        }

                    }



                    if (highCritCount > 0 || cvssGateCount > 0 || secretCount > 0) {

                        error("Pipeline bloquée (Security Gate) : ${highCritCount} vuln. HIGH/CRITICAL, ${cvssGateCount} vuln. avec CVSS >= ${cvssMinStr}, ${secretCount} secrets détectés.")

                    } else if (currentBuild.currentResult == 'FAILURE') {

                        error("Pipeline bloquée : échecs (FAILURE) lors des scans IaC, Vault, Kubernetes ou étapes critiques.")

                    } else {

                        echo "Pipeline propre : aucun secret, pas de HIGH/CRITICAL ni de CVSS >= ${cvssMinStr} (selon rapports Trivy)."

                    }

                }

            }

        }



        stage('6. Déploiement Multi-Environnements (dev / staging / prod)') {

            steps {

                script {

                    echo 'Déploiement dev puis staging, puis validation manuelle pour prod...'



                    catchError(buildResult: 'FAILURE') {

                        bat 'kubectl create namespace dev --dry-run=client -o yaml | kubectl apply -f -'

                        bat 'kubectl apply -f kubernetes -n dev'

                    }



                    catchError(buildResult: 'FAILURE') {

                        bat 'kubectl create namespace staging --dry-run=client -o yaml | kubectl apply -f -'

                        bat 'kubectl apply -f kubernetes -n staging'

                    }



                    input message: "Approuver le déploiement de l'application ${env.APP_NAME} sur PRODUCTION ?"



                    catchError(buildResult: 'FAILURE') {

                        bat 'kubectl create namespace prod --dry-run=client -o yaml | kubectl apply -f -'

                        bat 'kubectl apply -f kubernetes -n prod'

                    }



                    if (params.ENFORCE_NETPOL) {

                        catchError(buildResult: 'FAILURE') {

                            powershell '''

                                $ErrorActionPreference = 'Stop'

                                $json = kubectl get networkpolicy -n prod -o json | ConvertFrom-Json

                                if ($null -eq $json -or $json.items.Count -eq 0) {

                                    Write-Error "ENFORCE_NETPOL : aucune NetworkPolicy dans prod après déploiement."

                                }

                                Write-Host "OK: $($json.items.Count) NetworkPolicy(s) en prod."

                            '''

                        }

                    }

                }

            }

        }



        stage('7. Rotation des secrets (documentation)') {

            steps {

                echo '''

Rotation automatisée (option avancée) : à mettre en œuvre hors Jenkinsfile, par exemple :

- HashiCorp Vault : moteur de secrets dynamiques + politiques TTL / renouvellement.

- Sealed Secrets : renouveler les manifests chiffrés via kubeseal lors d'une rotation de mot de passe.

- Kubernetes : CronJob ou opérateur externe qui synchronise les secrets depuis Vault / cloud KMS.

Ce stage documente l'exigence ; la rotation réelle dépend de ton infra entreprise.

'''

            }

        }

    }



    post {

        always {

            script {

                archiveArtifacts allowEmptyArchive: true, artifacts: 'rbac-audit-*.txt,netpol-audit-all.txt'

                echo 'Envoi des rapports JSON natifs à DefectDojo...'



                def reports = [

                    'trivy-report.json'          : 'Trivy Scan',

                    'trivy-secrets.json'         : 'Trivy Scan',

                    'checkov-terraform.json'     : 'Checkov Scan',

                    'checkov-kubernetes.json'    : 'Checkov Scan',

                    'tfsec-report.json'          : 'TFSec Scan',

                    'terrascan-terraform.json'   : 'Terrascan Scan',

                    'kube-bench.json'            : 'kube-bench Scan',

                    'kube-hunter.json'           : 'KubeHunter Scan'

                ]



                withCredentials([string(credentialsId: 'defectdojo-api-token', variable: 'DD_API_TOKEN')]) {

                    reports.each { file, scan_type ->

                        if (fileExists(file)) {

                            def dojoUrl = env.DEFECTDOJO_URL ?: "http://localhost:8080"

                            bat "curl.exe -s -X POST \"${dojoUrl}/api/v2/reimport-scan/\" -H \"Authorization: Token %DD_API_TOKEN%\" -F \"scan_type=${scan_type}\" -F \"file=@${file}\" -F \"engagement_name=main\" -F \"product_name=${env.APP_NAME}\" -F \"product_type_name=${env.PRODUCT_TYPE}\" -F \"auto_create_context=true\""

                        }

                    }

                }

            }

        }

        success {

            echo "Pipeline réussie."

            script {

                if (env.SLACK_WEBHOOK_URL?.trim()) {

                    try {

                        bat """

                            curl.exe -s -X POST -H "Content-Type: application/json" -d "{\\"text\\":\\"DevSecOps OK : ${env.APP_NAME} build ${env.BUILD_NUMBER}\\"}" "%SLACK_WEBHOOK_URL%"

                        """

                    } catch (Exception e) {

                        echo "Slack (succès) non envoyé : ${e.message}"

                    }

                }

            }

        }

        failure {

            echo "Pipeline en échec : consulter DefectDojo et les logs Jenkins."

            script {

                echo 'Réponse incident : rollback Deployment (dev / staging / prod) si une révision précédente existe...'

                catchError(buildResult: null) {

                    bat """

                        kubectl rollout undo deployment/${env.K8S_DEPLOYMENT_NAME} -n prod --ignore-not-found=true

                        kubectl rollout undo deployment/${env.K8S_DEPLOYMENT_NAME} -n staging --ignore-not-found=true

                        kubectl rollout undo deployment/${env.K8S_DEPLOYMENT_NAME} -n dev --ignore-not-found=true

                    """

                }

                if (params.AGGRESSIVE_REMEDIATE) {

                    catchError(buildResult: null) {

                        bat "kubectl delete deployment ${env.K8S_DEPLOYMENT_NAME} -n prod --ignore-not-found=true"

                    }

                }



                if (env.SECURITY_ALERT_EMAIL?.trim()) {

                    catchError(buildResult: null) {

                        mail to: env.SECURITY_ALERT_EMAIL,

                             subject: "[DevSecOps] Échec pipeline ${env.APP_NAME} #${env.BUILD_NUMBER}",

                             body: "Le build a échoué. Voir Jenkins et DefectDojo. Job: ${env.BUILD_URL}"

                    }

                }

                if (env.SLACK_WEBHOOK_URL?.trim()) {

                    catchError(buildResult: null) {

                        bat """

                            curl.exe -s -X POST -H "Content-Type: application/json" -d "{\\"text\\":\\":warning: Échec DevSecOps ${env.APP_NAME} #${env.BUILD_NUMBER}\\"}" "%SLACK_WEBHOOK_URL%"

                        """

                    }

                }

            }

        }

    }

}

