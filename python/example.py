#!/usr/bin/env python3
"""
Example usage of the s2iam Python library.

This script demonstrates how to get a JWT from SingleStore's IAM service.
"""

import asyncio
import s2iam


async def main():
    """Main example function."""
    print("SingleStore IAM Python Library Example")
    print("=" * 40)

    try:
        # Simple JWT request for database access with workspace group ID
        token = await s2iam.get_jwt_database("example-workspace-group-id")
        print(f"✓ Successfully got database JWT: {token[:20]}...")

        # JWT for database access without workspace group ID
        token_no_workspace = await s2iam.get_jwt_database()
        print(
            f"✓ Successfully got database JWT (no workspace): {token_no_workspace[:20]}..."
        )

        # JWT for API gateway access
        api_jwt = await s2iam.get_jwt_api()
        print(f"✓ Successfully got API JWT: {api_jwt[:20]}...")

    except s2iam.CloudProviderNotFound:
        print("❌ Not running in a supported cloud environment")
        print("   This library requires AWS, GCP, or Azure cloud environment")

    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
