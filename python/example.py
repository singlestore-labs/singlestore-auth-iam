#!/usr/bin/env python3
"""
Example usage of the s2iam Python library.

This script demonstrates how to get a JWT token from SingleStore's IAM service.
"""

import asyncio
import s2iam


async def main():
    """Main example function."""
    print("SingleStore IAM Python Library Example")
    print("=" * 40)
    
    try:
        # Simple JWT token request for database access with workspace group ID
        jwt_token = await s2iam.get_jwt_database("example-workspace-group-id")
        print(f"✓ Successfully got database JWT token: {jwt_token[:20]}...")
        
        # JWT token for database access without workspace group ID
        jwt_token_no_workspace = await s2iam.get_jwt_database()
        print(f"✓ Successfully got database JWT token (no workspace): {jwt_token_no_workspace[:20]}...")
        
        # JWT token for API gateway access
        api_jwt = await s2iam.get_jwt_api()
        print(f"✓ Successfully got API JWT token: {api_jwt[:20]}...")
        
    except s2iam.NoCloudProviderDetectedError:
        print("❌ Not running in a supported cloud environment")
        print("   This library requires AWS, GCP, or Azure cloud environment")
        
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    asyncio.run(main())
