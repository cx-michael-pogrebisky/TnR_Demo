pipeline {
  agent { label 'windows' }
  environment {
    CX1_APIKEY = credentials('cx1-apikey')
    CXSAST_USERNAME = credentials('cxsast-username')
    CXSAST_PASSWORD = credentials('cxsast-password')
    CXSAST_URL = credentials('cxsast-url')
  }
  stages {
    stage('Checkmarx') {
      steps {
        checkout scm
        bat 'cx-onprem-orchestrator.exe run --scanners all --threshold sast-critical=1 --output-path cxoo-reports --parallel 8 --sast-team CxServer --sca-resolver "c:\\cxoo\\SCAResolver.exe" --sast-path "c:\\cxoo" --kics-queries "c:\\cxoo\\queries"'
      }
    }
  }
  post { always { archiveArtifacts artifacts: 'cxoo-reports/**', allowEmptyArchive: true } }
}
