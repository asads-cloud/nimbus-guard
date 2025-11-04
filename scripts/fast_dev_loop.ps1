if (-not (Test-Path -Path "$pwd\out")) { New-Item -ItemType Directory -Path "$pwd\out" | Out-Null }

docker run --rm `
  -e NG_REGIONS="eu-west-2,eu-west-1" `
  -e NG_FAIL_ON="HIGH" `
  -e NG_OUT="/app/out" `
  -e AWS_PROFILE="default" `
  -v "${env:USERPROFILE}\.aws:/home/appuser/.aws:ro" `
  -v "${pwd}\out:/app/out" `
  -v "${pwd}\scanner:/app" `
  nimbus-guard:latest
