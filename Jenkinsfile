pipeline {
    agent any

    // 1. Déclaration des outils (doivent correspondre aux noms dans Jenkins > Manage Jenkins > Tools)
    tools {
        jdk 'JDK-21'    // Remplace par le nom exact de ton JDK dans Jenkins (ex: "jdk17")
        maven 'Maven-3.9' // Remplace par le nom exact de ton Maven dans Jenkins (ex: "mvn3")
    }

    environment {
        APP_NAME        = "devsecops-app"
        IMAGE_NAME      = "${env.APP_NAME}:${env.BUILD_NUMBER}"
        
        DEFECTDOJO_URL  = "http://localhost:8080"
        DD_API_TOKEN    = "bda9c8b45403ba21c405f0cba4b4d1a41643c60b"
        PUSHGATEWAY_URL = "http://localhost:9091"
        PRODUCT_TYPE    = "Jenkins" // Requis par DefectDojo pour créer le produit
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('1. Build App & Docker Image') {
            steps {
                // Sur Windows Jenkins, utilisez "call mvn" si Maven est installé localement, ou juste "mvn" s'il vient de la directive tools.
                bat 'mvn clean package -DskipTests'
                bat "docker build -t ${env.IMAGE_NAME} ."
            }
        }

        stage('2. Analyse IaC (Scan JSON & Logique Bloquante)') {
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
                catchError(buildResult: 'FAILURE') {
                    bat "trivy image --format json --output trivy-report.json --exit-code 1 --severity HIGH,CRITICAL --scanners vuln,misconfig,secret ${env.IMAGE_NAME}"
                }
            }
        }
    }

    post {
        always {
            script {
                echo '📤 Envoi des rapports JSON à DefectDojo...'
                def reports = [
                    'trivy-report.json'       : 'Trivy Scan',
                    'checkov-terraform.json'  : 'Checkov Scan',
                    'tfsec-report.json'       : 'Tfsec Scan',
                    'terrascan-terraform.json': 'Terrascan Scan'
                ]
                
                // 2. Ajout de auto_create_context=true et product_type_name pour corriger l'erreur DefectDojo
                reports.each { file, scan_type ->
                    if (fileExists(file)) {
                        bat """curl.exe -s -X POST "${env.DEFECTDOJO_URL}/api/v2/reimport-scan/" -H "Authorization: Token ${env.DD_API_TOKEN}" -F "scan_type=${scan_type}" -F "file=@${file}" -F "engagement_name=main" -F "product_name=${env.APP_NAME}" -F "product_type_name=${env.PRODUCT_TYPE}" -F "auto_create_context=true" """
                    }
                }

                echo '📊 Poussée de la métrique globale vers Grafana (Prometheus Pushgateway)...'
                def buildSuccess = (currentBuild.currentResult == 'SUCCESS') ? 1 : 0
                
                // 3. Contournement du problème \r Windows (CRLF) en utilisant PowerShell Invoke-RestMethod
                powershell """
                \$body = "jenkins_build_success ${buildSuccess}`n"
                Invoke-RestMethod -Uri "${env.PUSHGATEWAY_URL}/metrics/job/devsecops_pipeline" -Method POST -Body \$body -ContentType "text/plain"
                """
            }
        }
        success {
            echo "✅ Pipeline réussie ! Code clean, images validées ✅."
        }
        failure {
            echo "❌ Pipeline bloquée : Des défauts sécuritaires ont été trouvés ou le build a échoué. Va voir DefectDojo ou Grafana pour les détails."
        }
    }
}