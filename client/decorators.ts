import { Decorator } from "@snek-at/function";
import AuthenticationContext, {
  AuthenticationInfo,
} from "./AuthenticationContext.js";
import {
  AuthenticationRequiredError,
  ResourceIdNotProvided,
  UnauthorizedError,
} from "./errors.js";

interface AuthenticationResult {
  authenticationInfo: AuthenticationInfo;
}

/**
 * A decorator that checks if the user is logged in and authenticated for the given resource.
 * @param resourceId The ID of the resource to check.
 */
export const loginRequired: Decorator<
  [resourceId: string],
  AuthenticationResult
> = async (context, [resourceId]) => {
  // Ensure that the resource ID is provided
  if (!resourceId) {
    throw new ResourceIdNotProvided();
  }

  // Retrieve authentication information from the context
  const authenticationContext = new AuthenticationContext(context);
  const authenticationInfos =
    await authenticationContext.getAllAuthenticationInfo();

  // Check if the user is authenticated for the given resource
  const authenticationInfoForResource = authenticationInfos.find(
    (info) => info.resourceId === resourceId
  );

  if (authenticationInfoForResource) {
    // If the user is authenticated, continue with the decorated function and return the result
    return {
      authenticationInfo: authenticationInfoForResource,
    };
  }

  // If the user is not authenticated, throw an authentication required error
  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if the user is logged in and authenticated on any resource.
 */
export const anyLoginRequired = async (
  context
): Promise<AuthenticationResult[]> => {
  // Retrieve authentication information from the context
  const authenticationContext = new AuthenticationContext(context);
  const authenticationInfos =
    await authenticationContext.getAllAuthenticationInfo();

  // Check if the user is authenticated on any resource
  if (authenticationInfos.length > 0) {
    // If the user is authenticated, continue with the decorated function and return the result
    return authenticationInfos.map((authenticationInfo) => ({
      authenticationInfo,
    }));
  }

  // If the user is not authenticated, throw an authentication required error
  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if a userId is authenticated
 */
export const userIdRequired: Decorator<
  [userId: string],
  AuthenticationResult
> = async (context, [userId]) => {
  // Retrieve authentication information from the context
  const authenticationContext = new AuthenticationContext(context);
  const authenticationInfos =
    await authenticationContext.getAllAuthenticationInfo();

  // Check if the user is authenticated for the given userId
  const authenticationInfoForUserId = authenticationInfos.find(
    (info) => info.userId === userId
  );

  if (authenticationInfoForUserId) {
    // If the user is authenticated, continue with the decorated function and return the result
    return {
      authenticationInfo: authenticationInfoForUserId,
    };
  }

  // If the user is not authenticated, throw an authentication required error
  throw new AuthenticationRequiredError();
};

/**
 * A decorator that checks if the user is an admin for the given resource.
 * @param resourceId The ID of the resource to check.
 */
export const adminRequired: typeof loginRequired = async (
  context,
  [resourceId]
) => {
  // Ensure that login is required
  const { authenticationInfo } = await loginRequired(context, [resourceId]);

  // Check if the user is an admin
  if (authenticationInfo.scope["admin"]?.includes("*")) {
    // If the user is an admin, continue with the decorated function
    return {
      authenticationInfo,
    };
  }

  // If the user is not an admin, throw an unauthorized error
  throw new UnauthorizedError();
};
