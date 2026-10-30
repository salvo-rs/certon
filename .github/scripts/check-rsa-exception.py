"""Check the dependency boundary before applying the RSA advisory exception."""

import json
import sys


def check(metadata):
    packages = {package["id"]: package for package in metadata["packages"]}
    nodes = metadata["resolve"]["nodes"]
    roots = [packages[item] for item in metadata["workspace_members"]]
    if len(roots) != 1 or roots[0]["name"] != "certon":
        raise ValueError("review the RSA exception for this workspace")
    root = roots[0]
    if root["version"] != "0.4.0":
        raise ValueError("review the RSA exception for the new certon release")
    if root["features"].get("rsa-keys") != ["dep:rsa"]:
        raise ValueError("review the changed rsa-keys feature")
    rsa = [package for package in packages.values() if package["name"] == "rsa"]
    if len(rsa) != 1 or not rsa[0]["version"].startswith("0.9."):
        raise ValueError("review the changed rsa dependency version")
    parents = {
        node["id"]
        for node in nodes
        if any(dependency["pkg"] == rsa[0]["id"] for dependency in node["deps"])
    }
    if parents != {root["id"]}:
        raise ValueError("the RSA exception does not cover another dependent crate")


if __name__ == "__main__":
    try:
        check(json.load(sys.stdin))
    except (KeyError, TypeError, ValueError) as error:
        sys.exit(f"RSA exception boundary failed: {error}")
    print("RSA exception boundary: certon 0.4.0 -> rsa 0.9 via rsa-keys")
