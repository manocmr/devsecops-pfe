pipeline {
    agent any

    tools {
        jdk 'JDK-21'
    }

    environment {
        IMAGE_NAME        = "devsecops-pipeline-test"
        IMAGE_TAG         = "latest"
        PUSHGATEWAY_URL   = "http://localhost:9091"
        JOB_LABEL         = "jenkins_devsecops"
    }

    stages {
        stage('Build App') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'mvn clean package -DskipTests'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "build_app", status)
                    }
                }
            }
        }

        stage('Terraform Validate') {
            steps {
                script {
                    def status = 0
                    try {
                        dir('terraform') {
                            bat 'terraform init -backend=false'
                            bat 'terraform validate'
                        }
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "terraform_validate", status)
                    }
                }
            }
        }

        stage('IaC Scan - Checkov') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'checkov -d terraform --framework terraform'
                        bat 'checkov -d kubernetes --framework kubernetes'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "iac_scan_checkov", status)
                    }
                }
            }
        }

        stage('IaC Scan - Tfsec') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'tfsec terraform'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "iac_scan_tfsec", status)
                    }
                }
            }
        }

        stage('IaC Scan - Terrascan') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'terrascan scan -i terraform -d terraform'
                        bat 'terrascan scan -i k8s -d kubernetes'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "iac_scan_terrascan", status)
                    }
                }
            }
        }

        stage('IaC Scan - Trivy') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'trivy config terraform --severity HIGH,CRITICAL --exit-code 1'
                        bat 'trivy config kubernetes --severity HIGH,CRITICAL --exit-code 1'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "iac_scan_trivy", status)
                    }
                }
            }
        }

        stage('Validate Kubernetes YAML') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'kubectl apply --dry-run=client -f kubernetes'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "validate_k8s_yaml", status)
                    }
                }
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'docker build -t %IMAGE_NAME%:%IMAGE_TAG% .'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "build_docker_image", status)
                    }
                }
            }
        }

        stage('Docker Scan - Trivy') {
            steps {
                script {
                    def status = 0
                    try {
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners misconfig,secret --severity HIGH,CRITICAL --format table --exit-code 1'
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln,misconfig,secret --format json --output trivy-full-report.json'
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity HIGH,CRITICAL --exit-code 1'
                    } catch (e) {
                        status = 1; throw e
                    } finally {
                        pushMetric("stage_status", "docker_scan_trivy", status)
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    pushMetric("stage_status", "deploy", 0)
                    echo 'Aucune violation critique - deploiement autorise'
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-*.txt, trivy-*.json', allowEmptyArchive: true
            script {
                // Métrique globale : 0 = success, 1 = failure
                def buildResult = (currentBuild.result == 'SUCCESS' || currentBuild.result == null) ? 0 : 1
                pushMetric("build_result", "global", buildResult)
                pushMetric("build_duration_seconds", "global", currentBuild.duration / 1000)
            }
        }
        failure {
            echo 'ECHEC - violation de securite detectee - pipeline bloque !'
        }
        success {
            echo 'SUCCES - pipeline DevSecOps conforme !'
        }
    }
}

// Fonction utilitaire pour pousser une métrique vers Pushgateway
def pushMetric(String metricName, String stageName, def value) {
    def payload = """# TYPE jenkins_${metricName} gauge
jenkins_${metricName}{job="${env.JOB_NAME}",stage="${stageName}",build="${env.BUILD_NUMBER}"} ${value}
"""
    def url = "${env.PUSHGATEWAY_URL}/metrics/job/${env.JOB_LABEL}/instance/${env.JOB_NAME}"
    
    // PowerShell pour Windows (puisque tu utilises bat)
    bat """
        powershell -Command "
            \$body = @'
${payload}
'@
            Invoke-WebRequest -Uri '${url}' -Method POST -Body \$body -ContentType 'text/plain'
        "
    """
}