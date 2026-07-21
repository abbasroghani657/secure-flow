"""Cloud Security Posture Management (CSPM) — AWS.

Given a set of the account owner's **read-only** credentials, enumerate the
account and flag the misconfigurations that most often cause cloud breaches:
public S3 buckets, security groups open to the internet, unencrypted storage,
publicly-reachable databases, IAM users without MFA / stale access keys, and
disabled audit logging.

Credentials are supplied per-scan by the account owner, used only for the scan,
and never persisted after it completes (the engine clears them like the other
authenticated scan types). This is the Prowler / ScoutSuite / Wiz category.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone

try:
    import boto3
    from botocore.config import Config
    from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
except Exception:  # pragma: no cover - boto3 must be installed for CSPM
    boto3 = None

from .checks import Finding

# Ports that should essentially never be open to 0.0.0.0/0.
_SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                    6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch",
                    1433: "MSSQL", 5984: "CouchDB", 11211: "Memcached"}
_KEY_MAX_AGE_DAYS = 90
_MAX_ITEMS = 500  # bound each resource type


@dataclass
class CSPMTarget:
    access_key: str
    secret_key: str
    region: str = "us-east-1"
    session_token: str | None = None


def _f(check_id, title, severity, resource, description, remediation, impact="", evidence="") -> Finding:
    return Finding(
        check_id=check_id, title=title, severity=severity, url=resource,
        description=description, impact=impact, evidence=evidence or resource,
        remediation=remediation, compliance_ref="OWASP A05:2021",
    )


def _client(session, name, region=None):
    cfg = Config(retries={"max_attempts": 2, "mode": "standard"}, connect_timeout=10, read_timeout=20)
    return session.client(name, region_name=region, config=cfg)


# --------------------------------------------------------------------------- #
# S3
# --------------------------------------------------------------------------- #
def _scan_s3(session) -> list[Finding]:
    out: list[Finding] = []
    s3 = _client(session, "s3")
    try:
        buckets = s3.list_buckets().get("Buckets", [])[:_MAX_ITEMS]
    except (ClientError, BotoCoreError):
        return out

    for b in buckets:
        name = b["Name"]
        res = f"s3://{name}"

        # Public Access Block — the account's guardrail against public exposure.
        blocked = False
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            blocked = all(pab.get(k) for k in
                          ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"))
        except (ClientError, KeyError):
            blocked = False  # NoSuchPublicAccessBlockConfiguration → not blocked

        # ACL granting AllUsers / AuthenticatedUsers.
        public_acl = False
        try:
            for g in s3.get_bucket_acl(Bucket=name).get("Grants", []):
                uri = (g.get("Grantee") or {}).get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    public_acl = True
        except ClientError:
            pass

        # Policy status (public bucket policy).
        public_policy = False
        try:
            public_policy = bool(
                s3.get_bucket_policy_status(Bucket=name).get("PolicyStatus", {}).get("IsPublic", False)
            )
        except (ClientError, KeyError):
            pass

        if (public_acl or public_policy) and not blocked:
            out.append(_f("cspm-s3-public-bucket", "S3 bucket is publicly accessible", "critical", res,
                          description=f"Bucket '{name}' is exposed publicly ({'ACL' if public_acl else 'policy'}) with no Public Access Block.",
                          impact="Public buckets are the single most common cause of large-scale cloud data leaks.",
                          remediation="Enable S3 Block Public Access (account + bucket) and remove public ACL/policy grants.",
                          evidence=f"public_acl={public_acl} public_policy={public_policy} block_public_access={blocked}"))
        elif not blocked:
            out.append(_f("cspm-s3-no-public-access-block", "S3 bucket without Block Public Access", "medium", res,
                          description=f"Bucket '{name}' does not have full S3 Block Public Access enabled.",
                          impact="Without the guardrail, a later ACL/policy change can silently make the bucket public.",
                          remediation="Enable all four Block Public Access settings on the bucket (and account-wide).",
                          evidence="BlockPublicAccess not fully enabled"))

        # Default encryption.
        try:
            s3.get_bucket_encryption(Bucket=name)
        except ClientError:
            out.append(_f("cspm-s3-unencrypted", "S3 bucket without default encryption", "medium", res,
                          description=f"Bucket '{name}' has no default server-side encryption configured.",
                          impact="Objects may be stored unencrypted at rest, failing PCI/HIPAA requirements.",
                          remediation="Enable default SSE-S3 or SSE-KMS encryption on the bucket.",
                          evidence="no ServerSideEncryptionConfiguration"))
    return out


# --------------------------------------------------------------------------- #
# EC2 — security groups + EBS volumes
# --------------------------------------------------------------------------- #
def _scan_security_groups(session, region) -> list[Finding]:
    out: list[Finding] = []
    ec2 = _client(session, "ec2", region)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])[:_MAX_ITEMS]
    except (ClientError, BotoCoreError):
        return out

    for sg in sgs:
        gid = sg.get("GroupId", "?")
        for perm in sg.get("IpPermissions", []):
            open_to_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in perm.get("IpRanges", [])) or \
                any(r.get("CidrIpv6") == "::/0" for r in perm.get("Ipv6Ranges", []))
            if not open_to_world:
                continue
            from_p = perm.get("FromPort")
            to_p = perm.get("ToPort")
            proto = perm.get("IpProtocol")
            if proto == "-1" or from_p is None:  # all ports/protocols
                hit = "ALL PORTS"
            else:
                names = [n for p, n in _SENSITIVE_PORTS.items() if from_p <= p <= to_p]
                hit = ", ".join(names) if names else None
            if hit:
                out.append(_f("cspm-sg-open-to-world",
                              f"Security group open to 0.0.0.0/0 ({hit})", "high", f"sg:{gid}",
                              description=f"Security group {gid} allows the whole internet to reach {hit}.",
                              impact="Internet-exposed admin/database ports are scanned and attacked within minutes.",
                              remediation="Restrict the ingress rule to specific trusted CIDRs or use a bastion/VPN.",
                              evidence=f"{gid}: {proto} {from_p}-{to_p} from 0.0.0.0/0"))
    return out


def _scan_ebs(session, region) -> list[Finding]:
    out: list[Finding] = []
    ec2 = _client(session, "ec2", region)
    try:
        vols = ec2.describe_volumes().get("Volumes", [])[:_MAX_ITEMS]
    except (ClientError, BotoCoreError):
        return out
    unencrypted = [v["VolumeId"] for v in vols if not v.get("Encrypted")]
    for vid in unencrypted[:50]:
        out.append(_f("cspm-ebs-unencrypted", "EBS volume not encrypted", "medium", f"vol:{vid}",
                      description=f"EBS volume {vid} is not encrypted at rest.",
                      impact="Unencrypted volumes/snapshots expose data in cleartext if leaked or shared.",
                      remediation="Enable EBS encryption (and account-level 'encryption by default').",
                      evidence=f"{vid}: Encrypted=false"))
    return out


# --------------------------------------------------------------------------- #
# IAM
# --------------------------------------------------------------------------- #
def _scan_iam(session) -> list[Finding]:
    out: list[Finding] = []
    iam = _client(session, "iam")
    try:
        users = iam.list_users().get("Users", [])[:_MAX_ITEMS]
    except (ClientError, BotoCoreError):
        return out

    now = datetime.now(timezone.utc)
    for u in users:
        uname = u["UserName"]
        # MFA
        try:
            mfa = iam.list_mfa_devices(UserName=uname).get("MFADevices", [])
            if not mfa:
                out.append(_f("cspm-iam-no-mfa", "IAM user without MFA", "high", f"iam:user/{uname}",
                              description=f"IAM user '{uname}' has no MFA device enabled.",
                              impact="Without MFA, a leaked password grants full access to the user's permissions.",
                              remediation="Require and enrol an MFA device for every human IAM user.",
                              evidence=f"{uname}: 0 MFA devices"))
        except ClientError:
            pass
        # Stale access keys
        try:
            for k in iam.list_access_keys(UserName=uname).get("AccessKeyMetadata", []):
                created = k.get("CreateDate")
                if created and (now - created).days > _KEY_MAX_AGE_DAYS and k.get("Status") == "Active":
                    age = (now - created).days
                    out.append(_f("cspm-iam-stale-access-key", "IAM access key not rotated", "medium",
                                  f"iam:user/{uname}",
                                  description=f"Access key for '{uname}' is {age} days old (> {_KEY_MAX_AGE_DAYS}).",
                                  impact="Long-lived credentials increase the window for a leaked key to be abused.",
                                  remediation="Rotate access keys regularly (<90 days) and prefer short-lived roles.",
                                  evidence=f"{k.get('AccessKeyId','?')}: {age} days old"))
        except ClientError:
            pass

    # Account password policy.
    try:
        pol = iam.get_account_password_policy().get("PasswordPolicy", {})
        weak = []
        if (pol.get("MinimumPasswordLength") or 0) < 14:
            weak.append("min length < 14")
        if not pol.get("RequireSymbols"):
            weak.append("no symbols required")
        if not pol.get("RequireNumbers"):
            weak.append("no numbers required")
        if weak:
            out.append(_f("cspm-iam-weak-password-policy", "Weak IAM password policy", "low", "iam:password-policy",
                          description="The account password policy is weaker than recommended: " + "; ".join(weak) + ".",
                          impact="Weak password requirements make credential-guessing attacks easier.",
                          remediation="Set a strong policy (≥14 chars, symbols, numbers, rotation, reuse-prevention).",
                          evidence="; ".join(weak)))
    except ClientError:
        out.append(_f("cspm-iam-no-password-policy", "No IAM account password policy", "medium",
                      "iam:password-policy",
                      description="The account has no custom IAM password policy.",
                      impact="Default settings allow weak passwords for IAM users.",
                      remediation="Configure an account password policy meeting your compliance baseline.",
                      evidence="no password policy set"))
    return out


# --------------------------------------------------------------------------- #
# RDS
# --------------------------------------------------------------------------- #
def _scan_rds(session, region) -> list[Finding]:
    out: list[Finding] = []
    rds = _client(session, "rds", region)
    try:
        dbs = rds.describe_db_instances().get("DBInstances", [])[:_MAX_ITEMS]
    except (ClientError, BotoCoreError):
        return out
    for db in dbs:
        did = db.get("DBInstanceIdentifier", "?")
        if db.get("PubliclyAccessible"):
            out.append(_f("cspm-rds-public", "RDS instance is publicly accessible", "high", f"rds:{did}",
                          description=f"RDS instance '{did}' is publicly accessible.",
                          impact="A public database endpoint massively enlarges the attack surface.",
                          remediation="Set PubliclyAccessible=false and place the DB in a private subnet.",
                          evidence=f"{did}: PubliclyAccessible=true"))
        if not db.get("StorageEncrypted"):
            out.append(_f("cspm-rds-unencrypted", "RDS storage not encrypted", "medium", f"rds:{did}",
                          description=f"RDS instance '{did}' does not have encrypted storage.",
                          impact="Unencrypted database storage fails PCI/HIPAA and exposes data if leaked.",
                          remediation="Enable storage encryption (requires re-create/snapshot-copy for existing DBs).",
                          evidence=f"{did}: StorageEncrypted=false"))
    return out


# --------------------------------------------------------------------------- #
# CloudTrail (audit logging)
# --------------------------------------------------------------------------- #
def _scan_cloudtrail(session, region) -> list[Finding]:
    out: list[Finding] = []
    ct = _client(session, "cloudtrail", region)
    try:
        trails = ct.describe_trails().get("trailList", [])
    except (ClientError, BotoCoreError):
        return out
    if not trails:
        out.append(_f("cspm-cloudtrail-disabled", "CloudTrail audit logging not enabled", "high",
                      "cloudtrail",
                      description="No CloudTrail trail was found in the account/region.",
                      impact="Without CloudTrail there is no audit record of API activity — you cannot detect or investigate a breach.",
                      remediation="Enable a multi-region CloudTrail trail with log-file validation.",
                      evidence="0 trails"))
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run_cspm_scan(target: CSPMTarget) -> list[Finding]:
    if boto3 is None:
        return [Finding("cspm-unavailable", "CSPM engine unavailable (boto3 not installed)", "info",
                        "cspm", description="The AWS SDK is not available on the server.",
                        remediation="Install boto3 to enable cloud posture scanning.",
                        compliance_ref="OWASP A05:2021", passed=True)]

    region = target.region or "us-east-1"
    session = boto3.Session(
        aws_access_key_id=target.access_key,
        aws_secret_access_key=target.secret_key,
        aws_session_token=target.session_token or None,
        region_name=region,
    )

    # Validate credentials up front.
    try:
        ident = _client(session, "sts").get_caller_identity()
    except (ClientError, NoCredentialsError, BotoCoreError) as exc:
        return [Finding("cspm-auth-failed", "AWS credentials were rejected", "info", "cspm",
                        description=f"Could not authenticate to AWS: {type(exc).__name__}.",
                        remediation="Provide valid read-only AWS credentials (a SecurityAudit/ReadOnlyAccess key).",
                        compliance_ref="OWASP A05:2021", passed=True)]

    findings: list[Finding] = []
    for fn, args in (
        (_scan_s3, (session,)),
        (_scan_security_groups, (session, region)),
        (_scan_ebs, (session, region)),
        (_scan_iam, (session,)),
        (_scan_rds, (session, region)),
        (_scan_cloudtrail, (session, region)),
    ):
        try:
            findings.extend(fn(*args))
        except (ClientError, BotoCoreError):
            continue

    acct = ident.get("Account", "?")
    if not findings:
        findings.append(Finding("cspm-clean", f"No misconfigurations found (account {acct})", "info",
                                f"aws:{acct}", description="The scanned AWS services passed all posture checks.",
                                remediation="Keep scanning cloud posture continuously.",
                                compliance_ref="OWASP A05:2021", passed=True))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (f.passed, order.get(f.severity, 5)))
    return findings
