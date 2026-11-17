# AWS version of the demo

The same six-stage pipeline, running in your AWS account instead of on a laptop.

```
release.zip in S3
   -> SecurityGate   CodeBuild: scan, AI triage (Claude on Bedrock), anomaly detection,
                     compliance, policy gate. Exit 1 stops the release here.
   -> Staging        CodeBuild: build the container image, push to ECR as :staging
   -> HumanApproval  CodePipeline manual approval, emailed through SNS
   -> Production     CodeBuild: tag the approved image :prod

Amazon Inspector / GuardDuty finding -> EventBridge -> Lambda -> SNS email
   (notifies a person; never changes production)
```

| Local stage | In AWS |
|---|---|
| pip-audit dependency check | Amazon Inspector `ScanSbom` (falls back to pip-audit, and says so) |
| Claude API triage | Claude on Amazon Bedrock (falls back to the rule table, and says so) |
| HTML report on disk | `evidence/build-N/` in the artifact bucket, plus findings in Security Hub |
| `policy.yaml` gate | Unchanged. The CodeBuild exit code blocks the pipeline |
| Running the fixed app | Image tagged `staging`, then `prod` after approval. No service is actually run |

## Status: run end to end on 17 November 2026 (us-east-1)

- Vulnerable release: blocked at SecurityGate. Dependency data came from Amazon Inspector and the
  triage from Claude on Bedrock (`claude-opus-5-5`): 10 P0, 6 P1, 5 P2, 3 P3.
- Fixed release: gate passed, image pushed to ECR as `staging`, pipeline waiting at HumanApproval.
- Alert Lambda: returns successfully for the sample Inspector event.
- Not yet exercised: the Production (promote) stage, the GuardDuty sample event, and the Security
  Hub export against an account that has Security Hub enabled. In an account without Security Hub
  the export is skipped with a visible access-denied message; the gate is unaffected.

Things learned on the first run:

- The Bedrock client needs `bedrock-mantle:CreateInference` on the build role (now in the template).
- A changed IAM policy can take a minute to apply. A run started seconds after a stack update may
  still show "access to the model was denied" and fall back to the rule table.
- Inspector `ScanSbom` works even when Amazon Inspector is not activated in the account.
- A copy of the evidence from these runs is in `aws/evidence/`.

Rehearse the whole flow again shortly before the session.

## Before you deploy

1. Pick a region where your account has access to the Claude model on Bedrock.
2. Optional but recommended for the full story: Security Hub, Amazon Inspector and GuardDuty
   enabled in that region. The template does **not** enable them, because they are account-wide
   settings you may already manage. Without Security Hub the export step is skipped with a visible
   message; the gate still works.
3. AWS CLI configured for the account.

## Deploy

```powershell
aws cloudformation deploy --stack-name shoplite-devsecops --template-file aws\devsecops.yaml --capabilities CAPABILITY_IAM --parameter-overrides NotificationEmail=you@example.com
```

Confirm the SNS subscription email, then read the outputs:

```powershell
aws cloudformation describe-stacks --stack-name shoplite-devsecops --query "Stacks[0].Outputs" --output table
```

## Demo run

Blocked release (the vulnerable service):

```powershell
.\.venv\Scripts\python.exe aws\package.py app
aws s3 cp aws\dist\release.zip s3://<SourceBucketName>/release.zip
aws codepipeline start-pipeline-execution --name shoplite-devsecops
```

Show: the SecurityGate stage fails, the build log prints the same six stages as the laptop run,
`evidence/build-N/report.html` is in the artifact bucket, and the findings are in Security Hub.

Passing release (the fixed service):

```powershell
.\.venv\Scripts\python.exe aws\package.py app_secure
aws s3 cp aws\dist\release.zip s3://<SourceBucketName>/release.zip
aws codepipeline start-pipeline-execution --name shoplite-devsecops
```

Show: SecurityGate passes, the image appears in ECR as `staging`, the pipeline stops at
HumanApproval and the approval email arrives. Approve it in the console; `prod` now points at the
same image digest.

The alert path, rehearsed with a clearly labelled sample event (real findings take minutes to appear):

```powershell
aws lambda invoke --function-name shoplite-devsecops-finding-responder --cli-binary-format raw-in-base64-out --payload file://aws/sample-events/inspector-finding.json out\responder.json
```

## Timing on a live call

A full pipeline run takes several minutes (CodeBuild start-up plus dependency install). Start the
blocked run before you begin the section, talk over the interactive presentation while it runs, and
keep a completed execution open in another tab in case the network is slow.

## Cost and teardown

CodeBuild, CodePipeline, S3, ECR, Lambda, SNS, Bedrock tokens, Inspector SBOM scans and Security
Hub finding ingestion are all usage-priced. This has not been costed; a handful of demo runs should
be small, but check your bill and tear the stack down afterwards.

```powershell
.\.venv\Scripts\python.exe -c "import boto3,sys; [boto3.resource('s3').Bucket(b).object_versions.delete() for b in sys.argv[1:]]" <SourceBucketName> <ArtifactBucketName>
aws cloudformation delete-stack --stack-name shoplite-devsecops
```

The first command permanently deletes every object version in the two demo buckets, which
CloudFormation needs before it can remove them. Findings already imported into Security Hub stay
there until they age out.

## What is deliberately not automated

- No production change happens without the approval stage.
- The alert Lambda only notifies. It does not start the pipeline or patch anything.
- Registry-wide Inspector enhanced scanning is not switched on by the template, since it changes
  scanning for every repository in the account.
