pipeline {
    agent any

    tools {
        jdk 'JDK-21'
    }

    environment {
        IMAGE_NAME      = "devsecops-pipeline-test"
        IMAGE_TAG       = "latest"
        PUSHGATEWAY_URL = "http://localhost:9091"
        JOB_LABEL       = "jenkins_devsecops"
    }

    stages {
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

        stage('IaC Scan - Checkov') {
            steps {
                script {
                    runStageWithMetric('iac_scan_checkov') {
                        bat 'checkov -d terraform --framework terraform'
                        bat 'checkov -d kubernetes --framework kubernetes'
                    }
                }
            }
        }

        stage('IaC Scan - Tfsec') {
            steps {
                script {
                    runStageWithMetric('iac_scan_tfsec') {
                        bat 'tfsec terraform'
                    }
                }
            }
        }

        stage('IaC Scan - Terrascan') {
            steps {
                script {
                    runStageWithMetric('iac_scan_terrascan') {
                        bat 'terrascan scan -i terraform -d terraform'
                        bat 'terrascan scan -i k8s -d kubernetes'
                    }
                }
            }
        }

        stage('IaC Scan - Trivy') {
            steps {
                script {
                    runStageWithMetric('iac_scan_trivy') {
                        bat 'trivy config terraform --severity HIGH,CRITICAL --exit-code 1'
                        bat 'trivy config kubernetes --severity HIGH,CRITICAL --exit-code 1'
                    }
                }
            }
        }

        stage('Validate Kubernetes YAML') {
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
                        bat 'docker build -t %IMAGE_NAME%:%IMAGE_TAG% .'
                    }
                }
            }
        }

        stage('Docker Scan - Trivy') {
            steps {
                script {
                    runStageWithMetric('docker_scan_trivy') {
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners misconfig,secret --severity HIGH,CRITICAL --format table --exit-code 1'
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln,misconfig,secret --format json --output trivy-full-report.json'
                        bat 'trivy image %IMAGE_NAME%:%IMAGE_TAG% --scanners vuln --severity HIGH,CRITICAL --exit-code 1'
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                script {
                    runStageWithMetric('deploy') {
                        echo 'Aucune violation critique - deploiement autorise'
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'trivy-*.txt, trivy-*.json', allowEmptyArchive: true

            script {
                def buildResult = (currentBuild.currentResult == 'SUCCESS') ? 0 : 1

                pushMetric('jenkins_build_result', 'global', buildResult)
                pushMetric('jenkins_build_duration_seconds', 'global', (currentBuild.duration / 1000) as long)
            }
        }

        failure {
            echo 'ECHEC - pipeline bloque'
        }

        success {
            echo 'SUCCES - pipeline DevSecOps conforme'
        }
    }
}

def runStageWithMetric(String metricStageName, Closure body) {
    def status = 0
    def start = System.currentTimeMillis()

    try {
        body()
    } catch (e) {
        status = 1
        throw e
    } finally {
        def durationSeconds = ((System.currentTimeMillis() - start) / 1000) as long

        pushMetric('jenkins_stage_status', metricStageName, status)
        pushMetric('jenkins_stage_duration_seconds', metricStageName, durationSeconds)
    }
}

def pushMetric(String metricName, String stageName, def value) {
    def safeJobName = (env.JOB_NAME ?: 'unknown_job').replaceAll('[^a-zA-Z0-9_-]', '_')
    def safeStageName = (stageName ?: 'unknown_stage').replaceAll('[^a-zA-Z0-9_-]', '_')
    def buildNumber = env.BUILD_NUMBER ?: '0'

    def payload = """${metricName}{job="${safeJobName}",stage="${safeStageName}",build="${buildNumber}"} ${value}
"""

    def url = "${env.PUSHGATEWAY_URL}/metrics/job/${env.JOB_LABEL}/instance/${safeJobName}"

    echo "Push URL: ${url}"
    echo "Payload: ${payload}"

    // Le push de métriques ne doit jamais casser le pipeline
    powershell returnStatus: true, script: """
\$body = @'
${payload}
'@

try {
    Invoke-RestMethod -Uri '${url}' -Method POST -Body \$body -ContentType 'text/plain'
    Write-Host 'Push OK'
    exit 0
}
catch {
    Write-Host 'Push FAILED'
    Write-Host \$_.Exception.Message
    exit 0
}
"""
}