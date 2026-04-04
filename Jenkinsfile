pipeline {
    agent any

    environment {
        // Chemin exact de ton JDK local
        JAVA_HOME       = "C:\\Program Files\\Eclipse Adoptium\\jdk-21.0.10.7-hotspot" 

        APP_NAME        = "devsecops-app"
        IMAGE_NAME      = "${env.APP_NAME}:${env.BUILD_NUMBER}"
        
        // Exclusivité DefectDojo
        DEFECTDOJO_URL  = "http://localhost:8080"
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
                                    bat 'kubectl apply --dry-run=client --validate=false -f kubernetes'
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
    }

    post {
        always {
            script {
                echo '📤 Envoi des rapports JSON natifs à DefectDojo...'
                
                // Mappage strict format JSON natif -> Parsers officiels DefectDojo
                def reports = [
                    'trivy-report.json'       : 'Trivy Scan',
                    'checkov-terraform.json'  : 'Checkov Scan',
                    'tfsec-report.json'       : 'Tfsec',
                    'terrascan-terraform.json': 'Terrascan Scan',
                    'kube-bench.json'         : 'Kube Bench Scan',
                    'kube-hunter.json'        : 'Kube Hunter Scan'
                ]
                
                // Récupération sécurisée du token via les Credentials Jenkins
                // Assure-toi de créer un "Secret text" dans Jenkins avec l'ID 'defectdojo-api-token'
                withCredentials([string(credentialsId: 'defectdojo-api-token', variable: 'DD_API_TOKEN')]) {
                    reports.each { file, scan_type ->
                        if (fileExists(file)) {
                            bat """curl.exe -s -X POST "${env.DEFECTDOJO_URL}/api/v2/reimport-scan/" -H "Authorization: Token ${env.DD_API_TOKEN}" -F "scan_type=${scan_type}" -F "file=@${file}" -F "engagement_name=main" -F "product_name=${env.APP_NAME}" -F "product_type_name=${env.PRODUCT_TYPE}" -F "auto_create_context=true" """
                        }
                    }
                }
            }
        }
        success {
            echo "✅ Pipeline réussie ! Code clean, aucune faille détectée."
        }
        failure {
            echo "❌ Pipeline bloquée : Des défauts sécuritaires ont été trouvés. Vérifie les détails dans DefectDojo."
        }
    }
}