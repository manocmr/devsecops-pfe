pipeline {
    agent any

    environment {
        // Chemins sécurisés via Jenkins Credentials (à configurer côté Jenkins)
        // Note: Assure-toi d'avoir créé ces credentials correspondants.
        JAVA_HOME       = credentials('java-home-cred')
        KUBECONFIG      = credentials('kubeconfig-cred')

        APP_NAME        = "devsecops-app"
        IMAGE_NAME      = "${env.APP_NAME}:${env.BUILD_NUMBER}"
        
        PRODUCT_TYPE    = "Jenkins" 
        // DEFECTDOJO_URL est désormais récupéré via les variables d'env globales de Jenkins
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
                stage('Checkov') {
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

        stage('5. Security Gate') {
            steps {
                script {
                    echo "Vérification avancée des rapports de sécurité (Parsing JSON)..."
                    def highCritCount = 0
                    def secretCount = 0

                    if (fileExists('trivy-report.json')) {
                        def trivyReport = readJSON file: 'trivy-report.json'
                        if (trivyReport.Results) {
                            trivyReport.Results.each { result ->
                                if (result.Vulnerabilities) {
                                    result.Vulnerabilities.each { vuln ->
                                        if (vuln.Severity == 'HIGH' || vuln.Severity == 'CRITICAL') {
                                            highCritCount++
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if (fileExists('trivy-secrets.json')) {
                        def secretsReport = readJSON file: 'trivy-secrets.json'
                        if (secretsReport.Results) {
                            secretsReport.Results.each { result ->
                                if (result.Secrets) {
                                    secretCount += result.Secrets.size()
                                }
                            }
                        }
                    }

                    if (highCritCount > 0 || secretCount > 0) {
                        error("Pipeline bloquée (Security Gate) : ${highCritCount} vulnérabilités (HIGH/CRITICAL) et ${secretCount} secrets exposés trouvés dans le code/image !")
                    } else if (currentBuild.currentResult == 'FAILURE') {
                        error("Pipeline bloquée : Des échecs ont été détectés lors des scans IaC ou vérifications Kubernetes.")
                    } else {
                        echo "Pipeline propre ✅ : Aucune vulnérabilité critique ou majeure détectée."
                    }
                }
            }
        }

        stage('6. Déploiement Multi-Environnements') {
            // Objectif PFE : Workflow multi-environnements (dev / staging / prod)
            steps {
                script {
                    echo 'Déploiement sécurisé en cours sur les environnements cibles...'
                    
                    // Création (si inexistant) et déploiement dans le namespace "staging"
                    catchError(buildResult: 'FAILURE') {
                        bat 'kubectl create namespace staging --dry-run=client -o yaml | kubectl apply -f -'
                        bat 'kubectl apply -f kubernetes -n staging'
                    }
                    
                    // Création et déploiement dans le namespace "prod" avec validation manuelle
                    input message: "Approuver le déploiement de l'application ${env.APP_NAME} sur l'environnement de PRODUCTION ?"
                    
                    catchError(buildResult: 'FAILURE') {
                        bat 'kubectl create namespace prod --dry-run=client -o yaml | kubectl apply -f -'
                        bat 'kubectl apply -f kubernetes -n prod'
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                echo '📤 Envoi des rapports JSON natifs à DefectDojo...'
                
                // Mappage strict format JSON natif -> Parsers officiels DefectDojo
                def reports = [
                    'trivy-report.json'       : 'Trivy Scan',
                    'trivy-secrets.json'      : 'Trivy Scan',
                    'checkov-terraform.json'  : 'Checkov Scan',
                    'tfsec-report.json'       : 'TFSec Scan',
                    'terrascan-terraform.json': 'Terrascan Scan',
                    'kube-bench.json'         : 'Kube Bench Scan',
                    'kube-hunter.json'        : 'Kube Hunter Scan'
                ]
                
                // Récupération sécurisée du token via les Credentials Jenkins
                // Assure-toi de créer un "Secret text" dans Jenkins avec l'ID 'defectdojo-api-token'
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
            echo "✅ Pipeline réussie ! Code clean, aucune faille détectée."
            
            // Objectif PFE : Automatisation de la réponse (Notifications de succès)
            // slackSend color: "good", message: "✅ Déploiement DevSecOps réussi : ${env.APP_NAME} propulsé sur Staging et Prod."
        }
        failure {
            echo "❌ Pipeline bloquée : Des défauts sécuritaires ont été trouvés. Vérifie les détails dans DefectDojo."
            
            // Objectif PFE : Réponse automatique aux incidents (Génération d'alertes en temps réel)
            echo "📧 Déclenchement automatique des alertes sécurité..."
            
            // 1. Notification par Email 
            // (Nécessite la configuration d'un serveur SMTP dans 'Jenkins > Manage > System')
            // mail to: 'security-team@example.com',
            //      subject: "🚨 ALERTE DEVSECOPS - Pipeline ${env.APP_NAME}",
            //      body: "Le déploiement a été bloqué pour cause de vulnérabilités ou de misconfigurations. Consultez DefectDojo et les logs Jenkins pour agir."
                 
            // 2. Notification Slack (Commenté pour ne pas casser le job s'il te manque le plugin)
            // (Nécessite le plugin 'Slack Notification' dans Jenkins)
            // slackSend color: "danger", message: "🚨 INCIDENT DEVSECOPS : Le déploiement de ${env.APP_NAME} a été bloqué automatiquement !"
        }
    }
}