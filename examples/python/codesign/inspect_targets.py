"""Triages several binaries and bundles: who signed them, with what, and whether they verify.

Each target is read concurrently, and a failing target does not hide the others. Edit
`TARGETS` before running.
"""

import asyncio

from signers import codesign
from signers.codesign import aio

TARGETS = [
    "/bin/ls",
    "/System/Applications/Calculator.app",
    "build/MyTool",
]


async def verdict(target: str) -> str:
    # A target that fails verification still gets its report, so the verdict is a value.
    try:
        await aio.verify(target, strict=codesign.Strict.ALL)
    except codesign.SignersError as error:
        return str(error)
    return "ok"


async def inspect(target: str) -> str:
    signature, requirements, result = await asyncio.gather(
        aio.display(target), aio.requirements(target), verdict(target)
    )
    lines = [f"  identifier: {signature.identifier}"]
    lines.append(f"  team: {signature.team_identifier or '-'}")
    if signature.signature is None:
        lines.append("  signature: ad hoc")
    else:
        leaf = (
            signature.signature.authorities[0]
            if signature.signature.authorities
            else None
        )
        lines.append(
            f"  signature: certificate of {leaf}"
            if leaf
            else "  signature: certificate"
        )
    runtime = codesign.SigningFlags.RUNTIME in signature.code_directory.flags
    lines.append(f"  hardened runtime: {runtime}")
    if signature.entitlements is not None:
        lines.append(f"  entitlements: {sorted(signature.entitlements)}")
    for requirement in requirements:
        if requirement.kind is codesign.RequirementKind.DESIGNATED:
            lines.append(f"  designated requirement: {requirement.expression}")
    lines.append(f"  verify: {result}")
    return "\n".join(lines)


async def main() -> None:
    # One call over all the targets would be shorter, but it reports a failure as
    # `BatchError` and drops the signatures of the targets that succeeded. One run per
    # target keeps every partial result.
    reports = await asyncio.gather(*map(inspect, TARGETS), return_exceptions=True)
    for target, report in zip(TARGETS, reports):
        print(target)
        if isinstance(report, BaseException):
            print(f"  unreadable: {report}")
        else:
            print(report)

    # Writes the certificate chain of each signed target to `certs/<name>.pem`.
    await aio.extract_certificates(TARGETS, save_to="certs")


if __name__ == "__main__":
    asyncio.run(main())
