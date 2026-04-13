// Credentials Jenkins requis (IDs à aligner avec ton instance) :
// - java-home-cred     : Secret text ou fichier selon ta config (JAVA_HOME)
// - kubeconfig         : Secret file = fichier kubeconfig du cluster
// - defectdojo-api-token : Secret text (API v2 DefectDojo)
// Optionnel : vault-token (si VAULT_ADDR est défini)
pipeline {

    agent any



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



        stage('4.5 Audit RBAC') {

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

                        """

                    }

                    echo 'Rapports : rbac-audit-*.txt (archiver en artefact Jenkins si besoin).'

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

                // Sans node/workspace (ex. échec très tôt), archiveArtifacts et bat échouent avec MissingContextVariableException.
                def agentName = env.NODE_NAME?.trim()
                def wsPath = env.WORKSPACE?.trim()
                if (!agentName || !wsPath) {
                    echo 'Post always : NODE_NAME ou WORKSPACE absent — archive et DefectDojo ignorés (contexte agent indisponible).'
                } else {
                    node(agentName) {
                        dir(wsPath) {
                            archiveArtifacts allowEmptyArchive: true, artifacts: 'rbac-audit-*.txt'

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

                            catchError(buildResult: null) {
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
                    }
                }

            }

        }

        success {

            echo "Pipeline réussie."

            script {

                catchError(buildResult: null) {
                    bat 'python scripts\\notify.py --status success'
                }

            }

        }

        failure {

            echo "Pipeline en échec : consulter DefectDojo et les logs Jenkins."

            script {

                def agentName = env.NODE_NAME?.trim() ?: 'built-in'

                node(agentName) {

                    catchError(buildResult: null) {
                        bat 'python scripts\\notify.py --status failure'
                    }

                }

            }

        }

    }

}

