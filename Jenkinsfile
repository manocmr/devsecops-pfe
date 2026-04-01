pipeline {
    agent any

    environment {
        APP_NAME        = "devsecops-app"
        IMAGE_NAME      = "${env.APP_NAME}:${env.BUILD_NUMBER}"
        
        // --- Variables d'intégration ---
        // Remplace par tes véritables URLs et Token DefectDojo
        DEFECTDOJO_URL  = "http://localhost:8080"
        DD_API_TOKEN    = "bda9c8b45403ba21c405f0cba4b4d1a41643c60b"
        PUSHGATEWAY_URL = "http://localhost:9091"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('1. Build Docker Image') {
            steps {
                bat 'mvn clean package -DskipTests'
                bat "docker build -t ${env.IMAGE_NAME} ."
            }
        }

        stage('2. Analyse IaC (Scan JSON & Logique Bloquante)') {
            // failFast false permet aux autres scans de finir de générer leurs JSON même si l'un échoue
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
                                    bat 'kubectl apply --dry-run=client -f kubernetes'
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
                // Détecte vulnérabilités -> génère le JSON -> bloque (exit 1) la pipeline si sévérité haute/critique
                catchError(buildResult: 'FAILURE') {
                    bat "trivy image --format json --output trivy-report.json --exit-code 1 --severity HIGH,CRITICAL --scanners vuln,misconfig,secret ${env.IMAGE_NAME}"
                }
            }
        }
    }

    post {
        always {
            // S'exécute TOUJOURS (même si la pipeline est bloquée (fail) par une vulnérabilité)
            script {
                echo '📤 Envoi des rapports JSON à DefectDojo...'
                def reports = [
                    'trivy-report.json'       : 'Trivy Scan',
                    'checkov-terraform.json'  : 'Checkov Scan',
                    'tfsec-report.json'       : 'Tfsec Scan',
                    'terrascan-terraform.json': 'Terrascan Scan'
                ]
                
                // Utilisation de la commande "curl" native sous Windows pour simplifier drastiquement l'envoi API
                reports.each { file, scan_type ->
                    if (fileExists(file)) {
                        bat """curl.exe -s -X POST "${env.DEFECTDOJO_URL}/api/v2/reimport-scan/" -H "Authorization: Token ${env.DD_API_TOKEN}" -F "scan_type=${scan_type}" -F "file=@${file}" -F "engagement_name=main" -F "product_name=${env.APP_NAME}" """
                    }
                }

                echo '📊 Poussée de la métrique globale vers Grafana (Prometheus Pushgateway)...'
                // Extrait un simple 1 (Succès) ou 0 (Échec) pour Grafana
                def buildSuccess = (currentBuild.currentResult == 'SUCCESS') ? 1 : 0
                bat """echo jenkins_build_success ${buildSuccess} | curl.exe --data-binary @- ${env.PUSHGATEWAY_URL}/metrics/job/devsecops_pipeline"""
            }
        }
        success {
            echo "✅ Pipeline réussie ! Code clean, images validées ✅."
        }
        failure {
            echo "❌ Pipeline bloquée : Des défauts sécuritaires ont été trouvés. Va voir DefectDojo ou Grafana pour les détails."
        }
    }
}